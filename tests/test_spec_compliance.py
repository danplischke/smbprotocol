# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Regression tests for the MS-SMB2 compliance findings in specs/COMPLIANCE_AUDIT.md.

Each test references the finding id (H1, M3, L7, ...) it covers.
"""

import threading
import time
import uuid

import pytest

import smbclient
from smbclient._io import _chunk_size, _parse_mode
from smbclient._pool import ClientConfig, replace_dfs_path
from smbprotocol import MAX_PAYLOAD_SIZE, Dialects
from smbprotocol.change_notify import SMB2ChangeNotifyResponse
from smbprotocol.connection import (
    Connection,
    HashAlgorithms,
    NegotiateContextType,
    Request,
    SecurityMode,
    SigningAlgorithms,
    SMB2Echo,
    SMB2EncryptionCapabilities,
    SMB2NegotiateContextRequest,
    SMB2NegotiateResponse,
    SMB2PreauthIntegrityCapabilities,
    SMB2SigningCapabilities,
    SMB3NegotiateRequest,
)
from smbprotocol.create_contexts import (
    CreateContextName,
    SMB2CreateDurableHandleReconnectV2,
)
from smbprotocol.dfs import ReferralEntry
from smbprotocol.exceptions import (
    BufferOverflow,
    SMB2ErrorResponse,
    SMB2SymbolicLinkErrorResponse,
    SMBAuthenticationError,
    SMBException,
)
from smbprotocol.file_info import FileAttributes, FileStreamInformation
from smbprotocol.header import (
    Commands,
    NtStatus,
    Smb2Flags,
    SMB2HeaderRequest,
    SMB2HeaderResponse,
)
from smbprotocol.ioctl import (
    SMB2IOCTLResponse,
    SMB2NetworkInterfaceInfo,
    SockAddrFamily,
    SockAddrIn,
    SockAddrStorage,
)
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    FileInformationClass,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    LockFlags,
    Open,
    QueryDirectoryFlags,
    RequestedOplockLevel,
    ShareAccess,
    SMB2CloseResponse,
    SMB2LockElement,
    SMB2OplockBreakAcknowledgment,
    SMB2OplockBreakNotification,
    SMB2QueryInfoResponse,
    SMB2ReadResponse,
)
from smbprotocol.reparse_point import SymbolicLinkReparseDataBuffer
from smbprotocol.session import Session, SessionFlags, SMB2SessionSetupResponse
from smbprotocol.tree import SMB2TreeConnectResponse, TreeConnect

from .conftest import ROOT_REFERRAL


def _response(command, status=NtStatus.STATUS_SUCCESS, message_id=1, session_id=1, data=b"", flags=0):
    header = SMB2HeaderResponse()
    header["command"] = command
    header["status"] = status
    header["message_id"] = message_id
    header["session_id"] = session_id
    header["flags"] = flags | Smb2Flags.SMB2_FLAGS_SERVER_TO_REDIR
    header["data"] = data
    return header


def _mock_connection(mocker, dialect=Dialects.SMB_3_1_1):
    connection = Connection(uuid.uuid4(), "server", 445, True)
    connection.dialect = dialect
    connection.transport = mocker.MagicMock()
    connection.transport.connected = True
    return connection


def _mock_tree(mocker, dialect=Dialects.SMB_3_1_1):
    tree = mocker.MagicMock()
    tree.session.connection.dialect = dialect
    tree.session.connection.supports_multi_channel = False
    tree.session.open_table = {}
    return tree


@pytest.fixture()
def clean_referral_cache():
    yield
    config = ClientConfig()
    config._referral_cache = []
    config._domain_cache = []


def _run_worker(connection, *messages):
    connection.transport.recv.side_effect = list(messages) + [b""]
    connection._process_message_thread()


class TestH1SignatureVerification:
    def _connection(self, mocker, signing_required=True):
        connection = _mock_connection(mocker)
        session = mocker.MagicMock()
        session.signing_required = signing_required
        session.signing_key = b"\x01" * 16
        connection.session_table[1] = session
        return connection

    def test_unsigned_response_rejected_when_signing_required(self, mocker):
        connection = self._connection(mocker)
        header = _response(Commands.SMB2_READ, message_id=2)

        with pytest.raises(SMBException, match="was not signed but signing is required"):
            connection.verify_signature(header, 1)

    def test_unsigned_response_allowed_when_signing_not_required(self, mocker):
        connection = self._connection(mocker, signing_required=False)
        header = _response(Commands.SMB2_READ, message_id=2)

        assert connection.verify_signature(header, 1) is False

    @pytest.mark.parametrize(
        "status",
        [
            NtStatus.STATUS_USER_SESSION_DELETED,
            NtStatus.STATUS_NETWORK_SESSION_EXPIRED,
            NtStatus.STATUS_INVALID_PARAMETER,
        ],
    )
    def test_unsigned_error_responses_allowed(self, mocker, status):
        connection = self._connection(mocker)
        header = _response(Commands.SMB2_READ, status=status, message_id=2)

        assert connection.verify_signature(header, 1) is False

    @pytest.mark.parametrize(
        "message_id, status",
        [
            (0xFFFFFFFFFFFFFFFF, NtStatus.STATUS_SUCCESS),
            (2, NtStatus.STATUS_PENDING),
        ],
    )
    def test_spec_skip_conditions(self, mocker, message_id, status):
        connection = self._connection(mocker)
        header = _response(Commands.SMB2_READ, status=status, message_id=message_id)

        assert connection.verify_signature(header, 1) is False

    def test_signed_response_verified(self, mocker):
        connection = self._connection(mocker)
        header = _response(Commands.SMB2_READ, message_id=2, flags=Smb2Flags.SMB2_FLAGS_SIGNED)
        header["signature"] = connection._generate_signature(header.pack(), b"\x01" * 16, 2, True, Commands.SMB2_READ)

        assert connection.verify_signature(header, 1) is True

    def test_worker_disconnects_on_stripped_signature(self, mocker):
        connection = self._connection(mocker)
        request_header = SMB2HeaderRequest()
        request_header["message_id"] = 2
        request = Request(request_header, SMB2ReadResponse, connection, session_id=1)
        connection.outstanding_requests[2] = request

        _run_worker(connection, _response(Commands.SMB2_READ, message_id=2).pack())

        assert isinstance(connection._t_exc, SMBException)
        assert "not signed" in str(connection._t_exc)


class TestH2H3ValidateNegotiate:
    def _tree(self, mocker, protected):
        connection = mocker.MagicMock()
        connection.dialect = Dialects.SMB_3_0_2
        connection.supports_encryption = False
        connection.transport.connected = True
        connection.negotiated_dialects = [Dialects.SMB_3_0_2]
        connection.client_capabilities = 0
        connection.client_guid = uuid.uuid4()
        connection.client_security_mode = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED

        session = mocker.MagicMock()
        session.connection = connection
        session.session_id = 1
        session.signing_key = b"\x01" * 16
        session.encrypt_data = False
        session.tree_connect_table = {}

        tree_request = mocker.MagicMock()
        ioctl_request = mocker.MagicMock()
        ioctl_request.response_protected = protected
        connection.send.side_effect = [tree_request, ioctl_request]

        ioctl_resp = SMB2IOCTLResponse()
        ioctl_resp["file_id"] = b"\xff" * 16
        ioctl_resp["output_offset"] = 112
        ioctl_resp["output_count"] = 24
        ioctl_resp["buffer"] = b"\x00" * 24
        tree_response = _response(Commands.SMB2_TREE_CONNECT, data=SMB2TreeConnectResponse().pack())
        tree_response["tree_id"] = 5
        connection.receive.side_effect = [tree_response, _response(Commands.SMB2_IOCTL, data=ioctl_resp.pack())]

        return TreeConnect(session, r"\\server\share"), connection

    def test_unprotected_response_disconnects(self, mocker):
        tree, connection = self._tree(mocker, protected=False)

        with pytest.raises(SMBException, match="neither signed nor encrypted"):
            tree.connect()

        assert not tree._connected
        assert tree.session.tree_connect_table == {}
        connection.disconnect.assert_called_once_with(False)

    def test_mismatched_response_disconnects(self, mocker):
        tree, connection = self._tree(mocker, protected=True)

        with pytest.raises(SMBException, match="Secure negotiate failed to verify"):
            tree.connect()

        assert not tree._connected
        assert tree.session.tree_connect_table == {}
        connection.disconnect.assert_called_once_with(False)

        # L12 - MaxOutputResponse is the size of the VALIDATE_NEGOTIATE_INFO response structure.
        ioctl_request = connection.send.call_args_list[1][0][0]
        assert ioctl_request["max_output_response"].get_value() == 24


class TestH4SessionSetup:
    def _session(self, mocker, dialect=Dialects.SMB_3_1_1, client_require_signing=True):
        connection = mocker.MagicMock()
        connection.dialect = dialect
        connection.require_signing = client_require_signing
        connection.client_require_signing = client_require_signing
        connection.client_security_mode = SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
        connection.supports_encryption = True
        session = Session(connection, "user", "pass", require_encryption=False)
        session.session_id = 1
        session.signing_key = b"\x01" * 16
        session.encryption_key = b"\x02" * 16
        return session, connection

    def test_311_unsigned_final_response_fails(self, mocker):
        session, connection = self._session(mocker)
        setup_response = SMB2SessionSetupResponse()
        response = _response(Commands.SMB2_SESSION_SETUP)

        with pytest.raises(SMBException, match="was not signed"):
            session._process_session_flags(setup_response, response)

    def test_311_final_response_verified_when_encrypted(self, mocker):
        session, connection = self._session(mocker)
        setup_response = SMB2SessionSetupResponse()
        setup_response["session_flags"] = SessionFlags.SMB2_SESSION_FLAG_ENCRYPT_DATA
        response = _response(Commands.SMB2_SESSION_SETUP, flags=Smb2Flags.SMB2_FLAGS_SIGNED)

        session._process_session_flags(setup_response, response)

        connection.verify_signature.assert_called_once_with(response, 1, force=True)
        assert session.encrypt_data

    def test_guest_allowed_when_client_does_not_require_signing(self, mocker):
        # L10 - a guest session is only a failure when the client requires signing.
        session, connection = self._session(mocker, client_require_signing=False)
        setup_response = SMB2SessionSetupResponse()
        setup_response["session_flags"] = SessionFlags.SMB2_SESSION_FLAG_IS_GUEST

        session._process_session_flags(setup_response, _response(Commands.SMB2_SESSION_SETUP))

        assert session.signing_required is False
        assert session.signing_key is None
        connection.disconnect.assert_not_called()

    def test_guest_terminates_connection_when_client_requires_signing(self, mocker):
        session, connection = self._session(mocker)
        setup_response = SMB2SessionSetupResponse()
        setup_response["session_flags"] = SessionFlags.SMB2_SESSION_FLAG_IS_GUEST

        with pytest.raises(SMBException, match="guest or anonymous"):
            session._process_session_flags(setup_response, _response(Commands.SMB2_SESSION_SETUP))

        connection.disconnect.assert_called_once_with(False)

    def test_setup_must_end_with_success(self, mocker):
        # L11 - the server must return STATUS_SUCCESS even if the local auth context has completed.
        context = mocker.MagicMock()
        type(context).complete = mocker.PropertyMock(side_effect=[False, True])
        context.step.return_value = b"token"
        mocker.patch("smbprotocol.session.spnego.client", return_value=context)

        session, connection = self._session(mocker)
        connection.preauth_integrity_session_hash_value = {1: []}
        request = mocker.MagicMock()
        request.message["message_id"].get_value.return_value = 1
        connection.send.return_value = request
        connection.receive.return_value = _response(
            Commands.SMB2_SESSION_SETUP,
            status=NtStatus.STATUS_MORE_PROCESSING_REQUIRED,
            data=SMB2SessionSetupResponse().pack(),
        )

        with pytest.raises(SMBAuthenticationError, match="without the server returning STATUS_SUCCESS"):
            session.connect()

    def test_security_buffer_located_by_offset(self):
        # M10 - SecurityBufferOffset is honoured.
        data = b"\x09\x00" + b"\x00\x00" + b"\x50\x00" + b"\x04\x00" + b"\x00" * 8 + b"\x01\x02\x03\x04"
        actual = SMB2SessionSetupResponse()
        actual.unpack(data)
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"


class TestH5UnsolicitedMessages:
    def test_unmatched_response_discarded(self, mocker):
        connection = _mock_connection(mocker)

        _run_worker(connection, _response(Commands.SMB2_READ, message_id=99).pack())

        assert connection._t_exc is None

    def test_pending_response_kept_with_wait_false(self, mocker):
        connection = _mock_connection(mocker)
        request_header = SMB2HeaderRequest()
        request_header["message_id"] = 2
        request = Request(request_header, SMB2ReadResponse, connection)
        request.response = _response(Commands.SMB2_READ, status=NtStatus.STATUS_PENDING, message_id=2)
        request.response_event.set()
        connection.outstanding_requests[2] = request

        connection.receive(request, wait=False)

        # The final response must still be able to find the request.
        assert connection.outstanding_requests[2] is request

    def test_cancel_completed_request(self, mocker):
        connection = _mock_connection(mocker)
        request_header = SMB2HeaderRequest()
        request_header["message_id"] = 2
        request = Request(request_header, SMB2ReadResponse, connection)

        # The request has already been completed and removed, cancel must not fail.
        request.cancel()
        assert connection.transport.send.call_count == 1

    @pytest.mark.parametrize(
        "current, new, expected, ack",
        [
            (RequestedOplockLevel.SMB2_OPLOCK_LEVEL_BATCH, RequestedOplockLevel.SMB2_OPLOCK_LEVEL_II, 0x01, True),
            (RequestedOplockLevel.SMB2_OPLOCK_LEVEL_EXCLUSIVE, RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE, 0x00, True),
            (RequestedOplockLevel.SMB2_OPLOCK_LEVEL_II, RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE, 0x00, False),
        ],
    )
    def test_oplock_break_acknowledged(self, mocker, current, new, expected, ack):
        connection = _mock_connection(mocker)
        smb_open = mocker.MagicMock()
        smb_open.file_id = b"\x01" * 16
        smb_open.oplock_level = current
        smb_open.tree_connect.session.session_id = 1
        smb_open.tree_connect.tree_connect_id = 2
        session = mocker.MagicMock()
        session.open_table = {smb_open.file_id: smb_open}
        connection.session_table[1] = session
        mock_send = mocker.patch.object(connection, "send")

        notification = SMB2OplockBreakNotification()
        notification["oplock_level"] = new
        notification["file_id"] = smb_open.file_id
        _run_worker(
            connection,
            _response(Commands.SMB2_OPLOCK_BREAK, message_id=0xFFFFFFFFFFFFFFFF, data=notification.pack()).pack(),
        )

        assert connection._t_exc is None
        assert smb_open.oplock_level == expected
        assert mock_send.call_count == (1 if ack else 0)
        if ack:
            ack_msg = mock_send.call_args[0][0]
            assert isinstance(ack_msg, SMB2OplockBreakAcknowledgment)
            assert ack_msg["oplock_level"].get_value() == expected
            assert ack_msg["file_id"].get_value() == smb_open.file_id
            assert mock_send.call_args[1] == {"sid": 1, "tid": 2}


class TestM1M2L7Lock:
    def _open(self, mocker, multi_channel=False):
        tree = _mock_tree(mocker)
        tree.session.connection.supports_multi_channel = multi_channel
        smb_open = Open(tree, "file.txt")
        smb_open.operation_buckets = [None] + [{"sequence_number": 0, "free": True} for _ in range(64)]
        return smb_open

    @staticmethod
    def _lock_element(flags=LockFlags.SMB2_LOCKFLAG_EXCLUSIVE_LOCK):
        element = SMB2LockElement()
        element["offset"] = 0
        element["length"] = 10
        element["flags"] = flags
        return element

    def test_lock_sequence_packing(self, mocker):
        smb_open = self._open(mocker)
        lock = smb_open.lock([self._lock_element()], lsn=3, lsi=5, send=False)[0]
        # LockSequenceNumber is the low 4 bits, LockSequenceIndex the upper 28 bits.
        assert lock["lock_sequence"].get_value() == (5 << 4) | 3

    def test_lsn_requires_lsi(self, mocker):
        smb_open = self._open(mocker)
        with pytest.raises(ValueError, match="requires a non-zero lsi"):
            smb_open.lock([self._lock_element()], lsn=3, send=False)

    def test_operation_bucket_used_with_multichannel(self, mocker):
        smb_open = self._open(mocker, multi_channel=True)
        lock, _ = smb_open.lock([self._lock_element()], send=False)
        assert lock["lock_sequence"].get_value() == 1 << 4
        assert smb_open.operation_buckets[1]["free"] is False

        request = mocker.MagicMock()
        request.message["data"].get_value.return_value = lock.pack()
        smb_open._release_operation_bucket(request)
        assert smb_open.operation_buckets[1] == {"sequence_number": 1, "free": True}

        lock, _ = smb_open.lock([self._lock_element()], send=False)
        assert lock["lock_sequence"].get_value() == (1 << 4) | 1

    def test_no_bucket_without_multichannel(self, mocker):
        smb_open = self._open(mocker)
        lock, _ = smb_open.lock([self._lock_element()], send=False)
        assert lock["lock_sequence"].get_value() == 0

    def test_empty_lock_list(self, mocker):
        with pytest.raises(ValueError, match="At least one lock element"):
            self._open(mocker).lock([], send=False)

    def test_multiple_locks_fail_immediately(self, mocker):
        lock, _ = self._open(mocker).lock([self._lock_element(), self._lock_element()], send=False)
        for element in lock["locks"].get_value():
            assert element["flags"].has_flag(LockFlags.SMB2_LOCKFLAG_FAIL_IMMEDIATELY)

    def test_invalid_lock_flags(self, mocker):
        element = self._lock_element(LockFlags.SMB2_LOCKFLAG_UNLOCK | LockFlags.SMB2_LOCKFLAG_FAIL_IMMEDIATELY)
        with pytest.raises(ValueError, match="Invalid lock flags combination"):
            self._open(mocker).lock([element], send=False)


class TestM3BufferOverflow:
    def _request(self, connection, command):
        request_header = SMB2HeaderRequest()
        request_header["message_id"] = 2
        request = Request(request_header, SMB2ReadResponse, connection)
        request.response = _response(command, status=NtStatus.STATUS_BUFFER_OVERFLOW, message_id=2)
        request.response_event.set()
        connection.outstanding_requests[2] = request
        return request

    @pytest.mark.parametrize(
        "command",
        [Commands.SMB2_READ, Commands.SMB2_IOCTL, Commands.SMB2_QUERY_INFO, Commands.SMB2_QUERY_DIRECTORY],
    )
    def test_buffer_overflow_returned(self, mocker, command):
        connection = _mock_connection(mocker)
        response = connection.receive(self._request(connection, command))
        assert response["status"].get_value() == NtStatus.STATUS_BUFFER_OVERFLOW

    def test_buffer_overflow_raised_for_other_commands(self, mocker):
        connection = _mock_connection(mocker)
        with pytest.raises(BufferOverflow):
            connection.receive(self._request(connection, Commands.SMB2_CREATE))

    def test_large_extended_attributes(self, smb_share):
        # The EAs no longer fit in a 64KiB query buffer, the query is retried with a larger buffer. Samba fails with
        # STATUS_INFO_LENGTH_MISMATCH while Windows returns the truncated entries with STATUS_BUFFER_OVERFLOW.
        file_path = f"{smb_share}\\file.txt"
        with smbclient.open_file(file_path, mode="w") as fd:
            fd.write("content")

        names = []
        for i in range(48):
            name = f"ATTR{i:03d}".encode()
            smbclient.setxattr(file_path, name, b"\x01" * 2048)
            names.append(name)

        actual = smbclient.listxattr(file_path)
        assert sorted(actual) == sorted(names)


class TestM4NegotiateValidation:
    def _response(self, dialect=Dialects.SMB_3_1_1, contexts=None):
        response = SMB2NegotiateResponse()
        response["dialect_revision"] = dialect
        if contexts is not None:
            response["negotiate_context_list"] = contexts
        return response

    @staticmethod
    def _context(context_type, data):
        context = SMB2NegotiateContextRequest()
        context["context_type"] = context_type
        context["data"] = data
        return context

    def _preauth(self, algorithms=None):
        data = SMB2PreauthIntegrityCapabilities()
        data["hash_algorithms"] = algorithms or [HashAlgorithms.SHA_512]
        data["salt"] = b"\x00" * 32
        return self._context(NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, data)

    def _connection(self, mocker):
        connection = _mock_connection(mocker)
        connection.negotiated_dialects = [Dialects.SMB_3_0_2, Dialects.SMB_3_1_1]
        return connection

    def test_dialect_not_offered(self, mocker):
        with pytest.raises(SMBException, match="was not offered"):
            self._connection(mocker)._validate_negotiate_response(self._response(Dialects.SMB_2_1_0), [], [])

    def test_valid(self, mocker):
        signing = SMB2SigningCapabilities()
        signing["signing_algorithms"] = [SigningAlgorithms.AES_GMAC]
        response = self._response(
            contexts=[self._preauth(), self._context(NegotiateContextType.SMB2_SIGNING_CAPABILITIES, signing)]
        )
        self._connection(mocker)._validate_negotiate_response(response, [], [SigningAlgorithms.AES_GMAC])

    def test_missing_preauth(self, mocker):
        with pytest.raises(SMBException, match="exactly one SMB2_PREAUTH_INTEGRITY_CAPABILITIES"):
            self._connection(mocker)._validate_negotiate_response(self._response(contexts=[]), [], [])

    def test_duplicate_context(self, mocker):
        signing = SMB2SigningCapabilities()
        signing["signing_algorithms"] = [SigningAlgorithms.AES_GMAC]
        context = self._context(NegotiateContextType.SMB2_SIGNING_CAPABILITIES, signing)
        response = self._response(contexts=[self._preauth(), context, context])

        with pytest.raises(SMBException, match="more than one context"):
            self._connection(mocker)._validate_negotiate_response(response, [], [SigningAlgorithms.AES_GMAC])

    def test_signing_algorithm_not_offered(self, mocker):
        signing = SMB2SigningCapabilities()
        signing["signing_algorithms"] = [SigningAlgorithms.HMAC_SHA256]
        response = self._response(
            contexts=[self._preauth(), self._context(NegotiateContextType.SMB2_SIGNING_CAPABILITIES, signing)]
        )

        with pytest.raises(SMBException, match="invalid signing algorithm"):
            self._connection(mocker)._validate_negotiate_response(response, [], [SigningAlgorithms.AES_GMAC])

    def test_cipher_not_offered(self, mocker):
        ciphers = SMB2EncryptionCapabilities()
        ciphers["ciphers"] = [0x0002]
        response = self._response(
            contexts=[self._preauth(), self._context(NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES, ciphers)]
        )

        with pytest.raises(SMBException, match="invalid encryption cipher"):
            self._connection(mocker)._validate_negotiate_response(response, [0x0001], [])

    def test_negotiate_context_located_by_offset(self):
        # M10 - extra padding before the negotiate context list is skipped using NegotiateContextOffset.
        response = SMB2NegotiateResponse()
        response["dialect_revision"] = Dialects.SMB_3_1_1
        response["negotiate_context_list"] = [self._preauth()]
        data = bytearray(response.pack())
        # Move the context list 8 bytes further and update the offset.
        offset = response["negotiate_context_offset"].get_value()
        data = data[: offset - 64] + b"\x00" * 8 + data[offset - 64 :]
        data[60:64] = (offset + 8).to_bytes(4, "little")

        actual = SMB2NegotiateResponse()
        actual.unpack(bytes(data))
        assert actual["negotiate_context_list"][0]["context_type"].get_value() == (
            NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        )


class TestM5M6SecurityMode:
    def test_tree_connect_signed_on_311(self, mocker):
        connection = mocker.MagicMock()
        connection.dialect = Dialects.SMB_3_1_1
        connection.supports_encryption = True
        session = mocker.MagicMock()
        session.connection = connection
        session.signing_key = b"\x01" * 16
        session.encrypt_data = False
        session.tree_connect_table = {}
        connection.receive.return_value = _response(Commands.SMB2_TREE_CONNECT, data=SMB2TreeConnectResponse().pack())

        TreeConnect(session, r"\\server\share").connect(require_secure_negotiate=False)

        assert connection.send.call_args[1]["force_signature"] is True

    def test_client_security_mode_kept(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], require_signing=False)
        connection.connect()
        try:
            # The server requires signing but the value sent in NEGOTIATE must be kept for VALIDATE_NEGOTIATE_INFO.
            assert connection.client_security_mode == SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
            assert connection.client_require_signing is False

            session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
            session.connect()
            tree = TreeConnect(session, smb_real[4])
            tree.connect()
            tree.disconnect()
        finally:
            connection.disconnect(True)


class TestM7MessageValidation:
    def test_unknown_protocol_id(self, mocker):
        connection = _mock_connection(mocker)
        message = _response(Commands.SMB2_READ).pack()

        _run_worker(connection, b"\xfcSMB" + message[4:])

        assert isinstance(connection._t_exc, SMBException)
        assert "ProtocolId" in str(connection._t_exc)

    def test_misaligned_compound(self, mocker):
        connection = _mock_connection(mocker)
        message = _response(Commands.SMB2_READ)
        message["next_command"] = 66

        _run_worker(connection, message.pack() + b"\x00" * 8)

        assert isinstance(connection._t_exc, SMBException)
        assert "8-byte aligned" in str(connection._t_exc)

    def test_session_id_must_match_transform(self, mocker):
        connection = _mock_connection(mocker)
        mocker.patch.object(connection, "_decrypt", return_value=_response(Commands.SMB2_READ, session_id=2).pack())
        # ProtocolId, Signature, Nonce, OriginalMessageSize, Reserved, Flags, SessionId
        transform = b"\xfdSMB" + b"\x00" * 36 + b"\x00\x00" + b"\x01\x00" + (1).to_bytes(8, "little")

        _run_worker(connection, transform)

        assert isinstance(connection._t_exc, SMBException)
        assert "does not match the transform header SessionId" in str(connection._t_exc)


class TestM8EncryptPooledSession:
    def test_enable_encryption(self, smb_real):
        server = smb_real[2]
        smbclient.delete_session(server, port=smb_real[3])
        session = smbclient.register_session(
            server, username=smb_real[0], password=smb_real[1], port=smb_real[3], encrypt=False
        )
        try:
            assert not session.encrypt_data

            session = smbclient.register_session(
                server, username=smb_real[0], password=smb_real[1], port=smb_real[3], encrypt=True
            )
            assert session.encrypt_data
            smbclient.listdir(smb_real[4], port=smb_real[3])
        finally:
            smbclient.delete_session(server, port=smb_real[3])


class TestM9Credits:
    def test_credit_request_at_least_one(self, mocker):
        connection = _mock_connection(mocker)
        connection.supports_multi_credit = False

        request = connection.send(SMB2Echo())

        assert request.message["credit_charge"].get_value() == 0
        assert request.message["credit_request"].get_value() == 1

    def test_no_phantom_credit(self, mocker):
        connection = _mock_connection(mocker)
        request = connection.send(SMB2Echo())
        assert connection.sequence_window == {"low": 1, "high": 1}

        response = _response(Commands.SMB2_OPLOCK_BREAK, message_id=request.message["message_id"].get_value())
        response["credit_response"] = 0
        _run_worker(connection, response.pack())

        assert connection.sequence_window == {"low": 1, "high": 1}

    def test_no_credits_and_nothing_pending(self, mocker):
        connection = _mock_connection(mocker)
        connection.sequence_window = {"low": 1, "high": 1}

        with pytest.raises(SMBException, match="credits are available"):
            connection.send(SMB2Echo())

    def test_waits_for_credits(self, mocker):
        connection = _mock_connection(mocker)
        connection.sequence_window = {"low": 1, "high": 1}
        pending = Request(SMB2HeaderRequest(), SMB2ReadResponse, connection)
        connection.outstanding_requests[0] = pending

        def grant():
            time.sleep(0.2)
            with connection.sequence_lock:
                connection.sequence_window["high"] += 1
                connection._credits_granted.notify_all()

        threading.Thread(target=grant).start()
        request = connection.send(SMB2Echo())
        assert request.message["message_id"].get_value() == 1

    def test_query_info_credit_charge(self, mocker):
        from smbprotocol.open import SMB2QueryInfoRequest

        connection = _mock_connection(mocker)
        connection.supports_multi_credit = True
        query = SMB2QueryInfoRequest()
        query["output_buffer_length"] = 1024 * 1024
        assert connection._calculate_credit_charge(query) == 16


class TestM10ResponseOffsets:
    def test_read_response_data_offset(self):
        # 16 byte fixed structure, DataOffset 0x58 leaves 8 bytes of padding before the data.
        data = b"\x11\x00" + b"\x58" + b"\x00" + b"\x04\x00\x00\x00" + b"\x00" * 8 + b"\x00" * 8 + b"\x01\x02\x03\x04"
        actual = SMB2ReadResponse()
        actual.unpack(data)
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"

    def test_ioctl_response_with_input(self):
        response = SMB2IOCTLResponse()
        response["file_id"] = b"\x00" * 16
        response["input_offset"] = 112
        response["input_count"] = 4
        response["output_offset"] = 120
        response["output_count"] = 4
        response["padding"] = b"\xff" * 8
        response["buffer"] = b"\x01\x02\x03\x04"

        actual = SMB2IOCTLResponse()
        actual.unpack(response.pack())
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"

    @pytest.mark.parametrize("structure", [SMB2QueryInfoResponse, SMB2ChangeNotifyResponse])
    def test_output_buffer_offset(self, structure):
        data = b"\x09\x00" + b"\x50\x00" + b"\x04\x00\x00\x00" + b"\x00" * 8 + b"\x01\x02\x03\x04"
        actual = structure()
        actual.unpack(data)
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"


class TestLowFindings:
    def test_l1_close_attributes_use_response_flag(self, mocker):
        tree = _mock_tree(mocker)
        smb_open = Open(tree, "file.txt")
        smb_open._connected = True
        tree.session.connection.receive.return_value = _response(Commands.SMB2_CLOSE, data=SMB2CloseResponse().pack())

        request = mocker.MagicMock()
        smb_open._close_response(request)

        # The server did not set SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB so the attributes must not be used.
        assert smb_open.end_of_file is None
        assert smb_open.creation_time is None

    @pytest.mark.parametrize("mode", ["wx", "aw", "rw", "rx", "xa"])
    def test_l3_mode_with_multiple_dispositions(self, mode):
        with pytest.raises(ValueError, match="must contain only one of r, w, x, or a"):
            _parse_mode(mode)

    @pytest.mark.parametrize(
        "mode, expected",
        [
            ("r", CreateDisposition.FILE_OPEN),
            ("rb+", CreateDisposition.FILE_OPEN),
            ("w+", CreateDisposition.FILE_OVERWRITE_IF),
            ("xb", CreateDisposition.FILE_CREATE),
            ("at", CreateDisposition.FILE_OPEN_IF),
        ],
    )
    def test_l3_mode(self, mode, expected):
        assert _parse_mode(mode) == expected

    def test_l4_dh2c_response_structure(self):
        actual = CreateContextName.get_response_structure(CreateContextName.SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2)
        assert isinstance(actual, SMB2CreateDurableHandleReconnectV2)

    def test_l5_open_state(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
        tree = TreeConnect(session, smb_real[4])
        smb_open = Open(tree, "l5-file.txt")
        try:
            session.connect()
            tree.connect()
            smb_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ
                | FilePipePrinterAccessMask.GENERIC_WRITE
                | FilePipePrinterAccessMask.DELETE,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE,
            )
            assert smb_open.create_disposition == CreateDisposition.FILE_OVERWRITE_IF
            assert smb_open.share_mode == ShareAccess.FILE_SHARE_READ
            assert len(smb_open.operation_buckets) == 65
        finally:
            connection.disconnect(True)

    def test_l6_chunk_size_without_multi_credit(self, mocker):
        connection = mocker.MagicMock()
        connection.supports_multi_credit = False
        connection.max_read_size = 8 * 1024 * 1024
        connection.sequence_window = {"low": 0, "high": 10}
        assert _chunk_size(connection, 1024 * 1024, "read")[0] == MAX_PAYLOAD_SIZE

    def test_l8_file_index_sets_flag(self, mocker):
        smb_open = Open(_mock_tree(mocker), "dir")
        query = smb_open.query_directory("*", FileInformationClass.FILE_NAMES_INFORMATION, file_index=10, send=False)[0]
        assert query["flags"].has_flag(QueryDirectoryFlags.SMB2_INDEX_SPECIFIED)
        assert query["file_index"].get_value() == 10

    def test_l9_list_uses_next_entry_offset(self):
        first = FileStreamInformation()
        first["stream_name"] = "::$DATA"
        second = FileStreamInformation()
        second["stream_name"] = ":ads:$DATA"
        # Pad the first entry to 16 bytes past its 8-byte aligned size.
        first_bytes = first.pack()
        first_len = len(first_bytes) + 16 + ((8 - len(first_bytes) % 8) % 8)
        first["next_entry_offset"] = first_len
        buffer = first.pack().ljust(first_len, b"\x00") + second.pack()

        response = SMB2QueryInfoResponse()
        response["buffer"] = buffer
        actual = response.parse_buffer(FileStreamInformation)
        assert [e["stream_name"].get_value() for e in actual] == ["::$DATA", ":ads:$DATA"]

    def test_l14_referral_lookup_case_insensitive(self, clean_referral_cache):
        config = ClientConfig()
        config.cache_referral(ROOT_REFERRAL)
        actual = config.lookup_referral(["DOMAIN.TEST", "DFS", "folder"])
        assert actual is not None
        assert actual.dfs_path == ReferralEntry(ROOT_REFERRAL).dfs_path

        assert replace_dfs_path(r"\DOMAIN.TEST\DFS\folder", r"\domain.test\dfs", r"\\server\share") == (
            r"\\server\share\folder"
        )

    def test_l15_error_contexts_aligned(self):
        data = (
            b"\x09\x00"
            b"\x02"
            b"\x00"
            b"\x1c\x00\x00\x00"
            b"\x04\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x01\x02\x03\x04" + b"\x00" * 4 + b"\x03\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x05\x06\x07"
        )
        actual = SMB2ErrorResponse()
        actual.unpack(data)
        contexts = actual["error_data"].get_value()
        assert [c["error_context_data"].get_value() for c in contexts] == [b"\x01\x02\x03\x04", b"\x05\x06\x07"]

    def test_l15_symlink_path_buffer_uses_reparse_data_length(self):
        response = SMB2SymbolicLinkErrorResponse()
        response.set_name("print", "substitute")
        # Add a null terminator after the names that is covered by ReparseDataLength.
        response["path_buffer"] = response["path_buffer"].get_value() + b"\x00\x00"
        response["reparse_data_length"] = len(response["path_buffer"]) + 12

        actual = SMB2SymbolicLinkErrorResponse()
        remaining = actual.unpack(response.pack() + b"trailing")
        assert actual.get_substitute_name() == "substitute"
        assert actual.get_print_name() == "print"
        assert remaining == b"trailing"

        buffer = SymbolicLinkReparseDataBuffer()
        buffer.set_name("substitute", "print")
        actual_buffer = SymbolicLinkReparseDataBuffer()
        actual_buffer.unpack(buffer.pack() + b"\x00\x00")
        assert actual_buffer.get_substitute_name() == "substitute"

    @pytest.mark.parametrize("dialect_count", [1, 2, 3, 4, 5])
    def test_l16_negotiate_context_alignment(self, dialect_count):
        request = SMB3NegotiateRequest()
        request["dialects"] = [Dialects.SMB_3_1_1] * dialect_count
        preauth = SMB2NegotiateContextRequest()
        preauth["context_type"] = NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        preauth["data"] = SMB2PreauthIntegrityCapabilities()
        preauth["data"]["hash_algorithms"] = [HashAlgorithms.SHA_512]
        preauth["data"]["salt"] = b"\x00" * 32
        request["negotiate_context_list"] = [preauth]

        offset = request["negotiate_context_offset"].get_value()
        assert offset % 8 == 0
        # The context list starts at the offset, relative to the start of the 64 byte SMB2 header.
        assert request.pack()[offset - 64 : offset - 62] == b"\x01\x00"

    def test_l17_network_interfaces_follow_next(self):
        def interface(index):
            addr = SockAddrIn()
            addr.set_ipaddress("10.0.2.15")
            sock_addr = SockAddrStorage()
            sock_addr["family"] = SockAddrFamily.INTER_NETWORK
            sock_addr["buffer"] = addr
            info = SMB2NetworkInterfaceInfo()
            info["if_index"] = index
            info["sock_addr_storage"] = sock_addr
            return info

        first = interface(1)
        second = interface(2)
        first["next"] = 160
        data = first.pack() + b"\x00" * 8 + second.pack()

        actual = SMB2NetworkInterfaceInfo.unpack_multiple(data)
        assert [i["if_index"].get_value() for i in actual] == [1, 2]


class TestH5OplockBreakIntegration:
    def test_oplock_break_does_not_kill_connection(self, smb_real):
        connection1 = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection1.connect()
        connection2 = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection2.connect()
        try:
            trees = []
            for connection in [connection1, connection2]:
                session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
                session.connect()
                tree = TreeConnect(session, smb_real[4])
                tree.connect()
                trees.append(tree)

            file_name = f"oplock-{uuid.uuid4()}.txt"
            open1 = Open(trees[0], file_name)
            open1.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ
                | FilePipePrinterAccessMask.GENERIC_WRITE
                | FilePipePrinterAccessMask.DELETE,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE,
                oplock_level=RequestedOplockLevel.SMB2_OPLOCK_LEVEL_BATCH,
            )
            if open1.oplock_level != RequestedOplockLevel.SMB2_OPLOCK_LEVEL_BATCH:
                pytest.skip("Server did not grant a batch oplock")

            # Opening the file from another connection makes the server break the oplock held by connection1. The
            # break must be acknowledged, otherwise the open waits for the server's break timeout.
            start = time.time()
            open2 = Open(trees[1], file_name)
            open2.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert time.time() - start < 10
            assert open1.oplock_level in [
                RequestedOplockLevel.SMB2_OPLOCK_LEVEL_II,
                RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE,
            ]

            # connection1 must still be usable.
            open1.write(b"data", 0)
            open1.close()
            open2.close()
        finally:
            connection1.disconnect(True)
            connection2.disconnect(True)
