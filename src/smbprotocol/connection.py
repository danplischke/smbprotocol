# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import binascii
import hashlib
import hmac
import logging
import os
import struct
import threading
import time
import typing as t
from collections import OrderedDict
from datetime import datetime
from threading import Lock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, aead, algorithms, modes

from smbprotocol import MAX_PAYLOAD_SIZE, Dialects
from smbprotocol._text import to_text
from smbprotocol.exceptions import (
    SMB2SymbolicLinkErrorResponse,
    SMBConnectionClosed,
    SMBException,
    SMBResponseException,
)
from smbprotocol.header import (
    Commands,
    NtStatus,
    Smb2Flags,
    SMB2HeaderAsync,
    SMB2HeaderRequest,
    SMB2HeaderResponse,
)
from smbprotocol.open import (
    LeaseBreakFlags,
    Open,
    RequestedOplockLevel,
    SMB2LeaseBreakAcknowledgment,
    SMB2LeaseBreakNotification,
    SMB2OplockBreakAcknowledgment,
    SMB2OplockBreakNotification,
)
from smbprotocol.structure import (
    BytesField,
    DateTimeField,
    EnumField,
    FlagField,
    IntField,
    ListField,
    Structure,
    StructureField,
    TextField,
    UuidField,
)
from smbprotocol.transport import Tcp

log = logging.getLogger(__name__)


class SecurityMode:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 NEGOTIATE Request SecurityMode
    Indicates whether SMB signing is enabled or required by the client.
    """

    SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
    SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002


class Capabilities:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 NEGOTIATE Request Capabilities
    Used in SMB3.x and above, used to specify the capabilities supported.
    """

    SMB2_GLOBAL_CAP_DFS = 0x00000001
    SMB2_GLOBAL_CAP_LEASING = 0x00000002
    SMB2_GLOBAL_CAP_LARGE_MTU = 0x00000004
    SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008
    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
    SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x00000020
    SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040


class NegotiateContextType:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1 SMB2 NEGOTIATE_CONTENT Request ContextType
    Specifies the type of context in an SMB2 NEGOTIATE_CONTEXT message.
    """

    SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
    SMB2_ENCRYPTION_CAPABILITIES = 0x0002
    SMB2_COMPRESSION_CAPABILITIES = 0x0003
    SMB2_NETNAME_NEGOTIATE_CONTEXT_ID = 0x0005
    SMB2_TRANSPORT_CAPABILITIES = 0x0006
    SMB2_RDMA_TRANSFORM_CAPABILITIES = 0x0007
    SMB2_SIGNING_CAPABILITIES = 0x0008


class HashAlgorithms:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    16-bit integer IDs that specify the integrity hash algorithm supported
    """

    SHA_512 = 0x0001


class Ciphers:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES
    16-bit integer IDs that specify the supported encryption algorithms.
    """

    AES_128_CCM = 0x0001
    AES_128_GCM = 0x0002
    AES_256_CCM = 0x0003
    AES_256_GCM = 0x0004


class SigningAlgorithms:
    """
    [MS-SMB2] 2.2.3.1.7 SMB2_SIGNING_CAPABILITIES

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cb9b5d66-b6be-4d18-aa66-8784a871cc10
    16-bit integer IDs that specify the supported signing algorithms.
    """

    HMAC_SHA256 = 0x0000
    AES_CMAC = 0x0001
    AES_GMAC = 0x0002


class SMB2NegotiateRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 Negotiate Request
    The SMB2 NEGOTIATE Request packet is used by the client to notify the
    server what dialects of the SMB2 Protocol the client understands. This is
    only used if the client explicitly sets the Dialect to use to a version
    less than 3.1.1. Dialect 3.1.1 added support for negotiate_context and
    SMB3NegotiateRequest should be used to support that.
    """

    COMMAND = Commands.SMB2_NEGOTIATE

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=36,
                    ),
                ),
                (
                    "dialect_count",
                    IntField(
                        size=2,
                        default=lambda s: len(s["dialects"].get_value()),
                    ),
                ),
                ("security_mode", FlagField(size=2, flag_type=SecurityMode)),
                ("reserved", IntField(size=2)),
                (
                    "capabilities",
                    FlagField(
                        size=4,
                        flag_type=Capabilities,
                    ),
                ),
                ("client_guid", UuidField()),
                ("client_start_time", IntField(size=8)),
                (
                    "dialects",
                    ListField(
                        size=lambda s: s["dialect_count"].get_value() * 2,
                        list_count=lambda s: s["dialect_count"].get_value(),
                        list_type=EnumField(size=2, enum_type=Dialects),
                    ),
                ),
            ]
        )

        super().__init__()


class SMB3NegotiateRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 Negotiate Request
    Like SMB2NegotiateRequest but with support for setting a list of
    Negotiate Context values. This is used by default and is for Dialects 3.1.1
    or greater.
    """

    COMMAND = Commands.SMB2_NEGOTIATE

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=36,
                    ),
                ),
                (
                    "dialect_count",
                    IntField(
                        size=2,
                        default=lambda s: len(s["dialects"].get_value()),
                    ),
                ),
                (
                    "security_mode",
                    FlagField(
                        size=2,
                        flag_type=SecurityMode,
                    ),
                ),
                ("reserved", IntField(size=2)),
                (
                    "capabilities",
                    FlagField(
                        size=4,
                        flag_type=Capabilities,
                    ),
                ),
                ("client_guid", UuidField()),
                (
                    "negotiate_context_offset",
                    IntField(
                        size=4,
                        default=SMB3NegotiateRequest._negotiate_context_offset_value,
                    ),
                ),
                (
                    "negotiate_context_count",
                    IntField(
                        size=2,
                        default=lambda s: len(s["negotiate_context_list"].get_value()),
                    ),
                ),
                ("reserved2", IntField(size=2)),
                (
                    "dialects",
                    ListField(
                        size=lambda s: s["dialect_count"].get_value() * 2,
                        list_count=lambda s: s["dialect_count"].get_value(),
                        list_type=EnumField(size=2, enum_type=Dialects),
                    ),
                ),
                (
                    "padding",
                    BytesField(
                        size=SMB3NegotiateRequest._padding_size,
                        default=SMB3NegotiateRequest._default_padding_size,
                    ),
                ),
                (
                    "negotiate_context_list",
                    ListField(
                        list_count=lambda s: s["negotiate_context_count"].get_value(),
                        unpack_func=SMB3NegotiateRequest._negotiate_context_list,
                    ),
                ),
            ]
        )
        super().__init__()

    @staticmethod
    def _negotiate_context_offset_value(structure):
        # The offset from the beginning of the SMB2 header to the first, 8-byte
        # aligned, negotiate context
        header_size = 64
        negotiate_size = structure["structure_size"].get_value()
        dialect_size = len(structure["dialects"])
        padding_size = SMB3NegotiateRequest._padding_size(structure)
        return header_size + negotiate_size + dialect_size + padding_size

    @staticmethod
    def _padding_size(structure):
        # Padding between the end of the dialects and the first Negotiate context value so that the first context is
        # 8-byte aligned relative to the start of the SMB2 header (64 byte header + 36 byte fixed structure).
        end_of_dialects = 64 + structure["structure_size"].get_value() + structure["dialect_count"].get_value() * 2
        return (8 - (end_of_dialects % 8)) % 8

    @staticmethod
    def _default_padding_size(structure):
        return b"\x00" * SMB3NegotiateRequest._padding_size(structure)

    @staticmethod
    def _negotiate_context_list(structure, data):
        context_count = structure["negotiate_context_count"].get_value()
        context_list = []
        for idx in range(0, context_count):
            field, data = SMB3NegotiateRequest._parse_negotiate_context_entry(data)
            context_list.append(field)

        return context_list

    @staticmethod
    def _parse_negotiate_context_entry(data):
        data_length = struct.unpack("<H", data[2:4])[0]
        negotiate_context = SMB2NegotiateContextRequest()
        negotiate_context.unpack(data[: data_length + 8])
        padded_size = 8 - (data_length % 8 or 8)

        return negotiate_context, data[8 + data_length + padded_size :]


class SMB2NegotiateContextRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1 SMB2 NEGOTIATE_CONTEXT Request Values
    The SMB2_NEGOTIATE_CONTEXT structure is used by the SMB2 NEGOTIATE Request
    and the SMB2 NEGOTIATE Response to encode additional properties.
    """

    COMMAND = Commands.SMB2_NEGOTIATE

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "context_type",
                    EnumField(
                        size=2,
                        enum_type=NegotiateContextType,
                    ),
                ),
                (
                    "data_length",
                    IntField(
                        size=2,
                        default=lambda s: len(s["data"].get_value()),
                    ),
                ),
                ("reserved", IntField(size=4)),
                (
                    "data",
                    StructureField(
                        size=lambda s: s["data_length"].get_value(),
                        structure_type=SMB2NegotiateContextRequest._data_structure_type,
                    ),
                ),
                # not actually a field but each list entry must start at the 8 byte
                # alignment
                (
                    "padding",
                    BytesField(
                        size=SMB2NegotiateContextRequest._padding_size,
                        default=SMB2NegotiateContextRequest._default_padding_size,
                    ),
                ),
            ]
        )
        super().__init__()

    @staticmethod
    def _data_structure_type(structure):
        con_type = structure["context_type"].get_value()
        if con_type == NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
            return SMB2PreauthIntegrityCapabilities
        elif con_type == NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES:
            return SMB2EncryptionCapabilities
        elif con_type == NegotiateContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:
            return SMB2NetnameNegotiateContextId
        elif con_type == NegotiateContextType.SMB2_SIGNING_CAPABILITIES:
            return SMB2SigningCapabilities

    @staticmethod
    def _padding_size(structure):
        data_size = len(structure["data"])
        return 8 - (data_size % 8 or 8)

    @staticmethod
    def _default_padding_size(structure):
        return b"\x00" * SMB2NegotiateContextRequest._padding_size(structure)


class SMB2PreauthIntegrityCapabilities(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    The SMB2_PREAUTH_INTEGRITY_CAPABILITIES context is specified in an SMB2
    NEGOTIATE request by the client to indicate which preauthentication
    integrity hash algorithms it supports and to optionally supply a
    preauthentication integrity hash salt value.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "hash_algorithm_count",
                    IntField(
                        size=2,
                        default=lambda s: len(s["hash_algorithms"].get_value()),
                    ),
                ),
                (
                    "salt_length",
                    IntField(
                        size=2,
                        default=lambda s: len(s["salt"]),
                    ),
                ),
                (
                    "hash_algorithms",
                    ListField(
                        size=lambda s: s["hash_algorithm_count"].get_value() * 2,
                        list_count=lambda s: s["hash_algorithm_count"].get_value(),
                        list_type=EnumField(size=2, enum_type=HashAlgorithms),
                    ),
                ),
                (
                    "salt",
                    BytesField(
                        size=lambda s: s["salt_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class SMB2EncryptionCapabilities(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES
    The SMB2_ENCRYPTION_CAPABILITIES context is specified in an SMB2 NEGOTIATE
    request by the client to indicate which encryption algorithms the client
    supports.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "cipher_count",
                    IntField(
                        size=2,
                        default=lambda s: len(s["ciphers"].get_value()),
                    ),
                ),
                (
                    "ciphers",
                    ListField(
                        size=lambda s: s["cipher_count"].get_value() * 2,
                        list_count=lambda s: s["cipher_count"].get_value(),
                        list_type=EnumField(size=2, enum_type=Ciphers),
                    ),
                ),
            ]
        )
        super().__init__()


class SMB2NetnameNegotiateContextId(Structure):
    """
    [MS-SMB2] 2.2.3.1.4 SMB2_NETNAME_NEGOTIATE_CONTEXT_ID

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ca6726bd-b9cf-43d9-b0bc-d127d3c993b3

    The SMB2_NETNAME_NEGOTIATE_CONTEXT_ID context is specified in an SMB2
    NEGOTIATE request to indicate the server name the client connects to.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("net_name", TextField()),
            ]
        )
        super().__init__()


class SMB2SigningCapabilities(Structure):
    """
    [MS-SMB2] 2.2.3.1.7 SMB2_SIGNING_CAPABILITIES

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cb9b5d66-b6be-4d18-aa66-8784a871cc10

    The SMB2_SIGNING_CAPABILITIES context is specified in an SMB2 NEGOTIATE
    request by the client to indicate which signing algorithms the client supports.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "signing_algorithm_count",
                    IntField(
                        size=2,
                        default=lambda s: len(s["signing_algorithms"].get_value()),
                    ),
                ),
                (
                    "signing_algorithms",
                    ListField(
                        size=lambda s: s["signing_algorithm_count"].get_value() * 2,
                        list_count=lambda s: s["signing_algorithm_count"].get_value(),
                        list_type=EnumField(size=2, enum_type=SigningAlgorithms),
                    ),
                ),
            ]
        )
        super().__init__()


class SMB2NegotiateResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.4 SMB2 NEGOTIATE Response
    The SMB2 NEGOTIATE Response packet is sent by the server to notify the
    client of the preferred common dialect.
    """

    COMMAND = Commands.SMB2_NEGOTIATE

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=65,
                    ),
                ),
                (
                    "security_mode",
                    FlagField(
                        size=2,
                        flag_type=SecurityMode,
                    ),
                ),
                (
                    "dialect_revision",
                    EnumField(
                        size=2,
                        enum_type=Dialects,
                    ),
                ),
                (
                    "negotiate_context_count",
                    IntField(
                        size=2,
                        default=SMB2NegotiateResponse._negotiate_context_count_value,
                    ),
                ),
                ("server_guid", UuidField()),
                ("capabilities", FlagField(size=4, flag_type=Capabilities)),
                ("max_transact_size", IntField(size=4)),
                ("max_read_size", IntField(size=4)),
                ("max_write_size", IntField(size=4)),
                ("system_time", DateTimeField()),
                ("server_start_time", DateTimeField()),
                (
                    "security_buffer_offset",
                    IntField(
                        size=2,
                        default=128,  # (header size 64) + (structure size 64)
                    ),
                ),
                (
                    "security_buffer_length",
                    IntField(
                        size=2,
                        default=lambda s: len(s["buffer"].get_value()),
                    ),
                ),
                (
                    "negotiate_context_offset",
                    IntField(
                        size=4,
                        default=SMB2NegotiateResponse._negotiate_context_offset_value,
                    ),
                ),
                (
                    "buffer_padding",
                    BytesField(
                        size=SMB2NegotiateResponse._buffer_padding_size,
                        default=lambda s: b"\x00" * SMB2NegotiateResponse._buffer_padding_size(s),
                    ),
                ),
                (
                    "buffer",
                    BytesField(
                        size=lambda s: s["security_buffer_length"].get_value(),
                    ),
                ),
                (
                    "padding",
                    BytesField(
                        size=SMB2NegotiateResponse._padding_size,
                        default=SMB2NegotiateResponse._default_padding_size,
                    ),
                ),
                (
                    "negotiate_context_list",
                    ListField(
                        list_count=lambda s: s["negotiate_context_count"].get_value(),
                        unpack_func=SMB2NegotiateResponse._negotiate_context_list,
                    ),
                ),
            ]
        )
        super().__init__()

    @staticmethod
    def _negotiate_context_count_value(structure):
        # If the dialect_revision is SMBv3.1.1, this field specifies the
        # number of negotiate contexts in negotiate_context_list; otherwise
        # this field must not be used and must be reserved (0).
        if structure["dialect_revision"].get_value() == Dialects.SMB_3_1_1:
            return len(structure["negotiate_context_list"].get_value())
        else:
            return None

    @staticmethod
    def _negotiate_context_offset_value(structure):
        # If the dialect_revision is SMBv3.1.1, this field specifies the offset
        # from the beginning of the SMB2 header to the first 8-byte
        # aligned negotiate context entry in negotiate_context_list; otherwise
        # this field must not be used and must be reserved (0).
        if structure["dialect_revision"].get_value() == Dialects.SMB_3_1_1:
            buffer_offset = structure["security_buffer_offset"].get_value()
            buffer_size = structure["security_buffer_length"].get_value()
            padding_size = SMB2NegotiateResponse._minimal_padding_size(structure)
            return buffer_offset + buffer_size + padding_size
        else:
            return None

    @staticmethod
    def _buffer_padding_size(structure):
        # MS-SMB2 3.2.5.2 - the security buffer is located by SecurityBufferOffset which is relative to the start of
        # the SMB2 header, the fixed header and response structure take up the first 128 bytes.
        if structure["security_buffer_length"].get_value() == 0:
            return 0

        return max(0, structure["security_buffer_offset"].get_value() - 128)

    @staticmethod
    def _padding_size(structure):
        # Padding between the end of the buffer value and the first Negotiate
        # context value so that the first value is 8-byte aligned. Padding is
        # not required if there are not negotiate contexts
        if structure["negotiate_context_count"].get_value() == 0:
            return 0

        # MS-SMB2 3.2.5.2 - the context list is located by NegotiateContextOffset, use it when it is set rather than
        # assuming the server used the minimal padding.
        buffer_end = (
            128
            + SMB2NegotiateResponse._buffer_padding_size(structure)
            + structure["security_buffer_length"].get_value()
        )
        context_offset = structure["negotiate_context_offset"].get_value()
        if context_offset and context_offset >= buffer_end:
            return context_offset - buffer_end

        return SMB2NegotiateResponse._minimal_padding_size(structure)

    @staticmethod
    def _minimal_padding_size(structure):
        mod = structure["security_buffer_length"].get_value() % 8
        return 0 if mod == 0 else 8 - mod

    @staticmethod
    def _default_padding_size(structure):
        return b"\x00" * SMB2NegotiateResponse._padding_size(structure)

    @staticmethod
    def _negotiate_context_list(structure, data):
        context_count = structure["negotiate_context_count"].get_value()
        context_list = []
        for idx in range(0, context_count):
            field, data = SMB2NegotiateResponse._parse_negotiate_context_entry(data)
            context_list.append(field)

        return context_list

    @staticmethod
    def _parse_negotiate_context_entry(data):
        data_length = struct.unpack("<H", data[2:4])[0]
        negotiate_context = SMB2NegotiateContextRequest()
        negotiate_context.unpack(data[: data_length + 8])
        padded_size = data_length % 8
        if padded_size != 0:
            padded_size = 8 - padded_size

        return negotiate_context, data[8 + data_length + padded_size :]


class SMB2Echo(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.28 SMB2 Echo Request/Response
    Request and response for an SMB ECHO message.
    """

    COMMAND = Commands.SMB2_ECHO

    def __init__(self):
        self.fields = OrderedDict([("structure_size", IntField(size=2, default=4)), ("reserved", IntField(size=2))])
        super().__init__()


class SMB2CancelRequest(Structure):
    """
    [MS-SMB2] 2.2.30 - SMB2 CANCEL Request
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/91913fc6-4ec9-4a83-961b-370070067e63

    The SMB2 CANCEL Request packet is sent by the client to cancel a previously sent message on the same SMB2 transport
    connection.
    """

    COMMAND = Commands.SMB2_CANCEL

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=4,
                    ),
                ),
                ("reserved", IntField(size=2)),
            ]
        )
        super().__init__()


class SMB2TransformHeader(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.41 SMB2 TRANSFORM_HEADER
    The SMB2 Transform Header is used by the client or server when sending
    encrypted message. This is only valid for the SMB.x dialect family.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("protocol_id", BytesField(size=4, default=b"\xfdSMB")),
                ("signature", BytesField(size=16, default=b"\x00" * 16)),
                ("nonce", BytesField(size=16)),
                ("original_message_size", IntField(size=4)),
                ("reserved", IntField(size=2, default=0)),
                ("flags", IntField(size=2, default=1)),
                ("session_id", IntField(size=8)),
                ("data", BytesField()),  # not in spec
            ]
        )
        super().__init__()


class Connection:
    # MS-SMB2 3.3.4.4 - commands where STATUS_BUFFER_OVERFLOW is returned with a valid, truncated, response body.
    _BUFFER_OVERFLOW_COMMANDS = frozenset(
        [
            Commands.SMB2_READ,
            Commands.SMB2_IOCTL,
            Commands.SMB2_QUERY_INFO,
            Commands.SMB2_QUERY_DIRECTORY,
        ]
    )

    # Error responses that servers send unsigned even when the session requires signing because the session itself is
    # gone or the request could not be associated with it. They are still raised to the caller as errors.
    _UNSIGNED_ERROR_STATUSES = frozenset(
        [
            NtStatus.STATUS_USER_SESSION_DELETED,
            NtStatus.STATUS_NETWORK_SESSION_EXPIRED,
            NtStatus.STATUS_INVALID_PARAMETER,
        ]
    )

    def __init__(self, guid, server_name, port=445, require_signing=True):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.2 Per SMB2 Transport Connection
        Used as the transport interface for a server. Some values have been
        omitted as they can be retrieved by the Server object stored in
        self.server

        :param guid: A unique guid that represents the client
        :param server_name: The server to start the connection
        :param port: The port to use for the transport, default is 445
        :param require_signing: Whether signing is required on SMB messages
            sent over this connection
        """
        log.info(
            "Initialising connection, guid: %s, require_signing: %s, server_name: %s, port: %d",
            guid,
            require_signing,
            server_name,
            port,
        )
        self.server_name = server_name
        self.port = port
        self.transport = None  # Instanciated in .connect()

        # Experimental customizable value. Might be removed in the future
        self._receive_timeout = int(os.environ.get("SMB_EXPERIMENTAL_TRANSPORT_RECEIVE_TIMEOUT", 600))

        # Table of Session entries, the order is important for smbclient.
        self.session_table = OrderedDict()

        # Table of Requests that have yet to be picked up by the application,
        # it MAY contain a response from the server as well
        self.outstanding_requests = dict()

        # Table of available sequence numbers
        self.sequence_window = dict(low=0, high=1)
        self.sequence_lock = Lock()
        # Signalled when the server grants credits so a request waiting for available message ids can continue.
        self._credits_granted = threading.Condition(self.sequence_lock)

        # Byte array containing the negotiate token and remembered for
        # authentication
        self.gss_negotiate_token = None

        self.server_guid = None
        self.max_transact_size = None
        self.max_read_size = None
        self.max_write_size = None
        # RequireSigning is set to True if either the client or server requires signing. The client's own setting
        # (RequireMessageSigning in MS-SMB2) is kept separately as it controls whether guest sessions are allowed.
        self.require_signing = require_signing
        self.client_require_signing = require_signing

        # SMB 2.1+
        self.dialect = None
        self.supports_file_leasing = None
        # just go with False as a default for Dialect 2.0.2
        self.supports_multi_credit = False
        self.client_guid = guid

        # SMB 3.x+
        self.salt = None
        self.supports_directory_leasing = None
        self.supports_multi_channel = None
        self.supports_persistent_handles = None
        self.supports_encryption = None

        # used for SMB 3.x for secure negotiate verification on tree connect
        self.negotiated_dialects = []
        self.client_capabilities = (
            Capabilities.SMB2_GLOBAL_CAP_LARGE_MTU
            | Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION
            | Capabilities.SMB2_GLOBAL_CAP_DFS
        )

        self.client_security_mode = (
            SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
            if require_signing
            else SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        )
        self.server_security_mode = None
        self.server_capabilities = None

        # SMB 3.1.1+
        # The hashing algorithm object that was negotiated
        self.preauth_integrity_hash_id = None

        # Preauth integrity hash value computed for the SMB2 NEGOTIATE request
        # contains the messages used to compute the hash
        self.preauth_integrity_hash_value = []
        # Table of raw header bytes for unauthenticated session setup messages,
        # indexed by message_id.
        self.preauth_integrity_session_hash_value: t.Dict[int, t.List[bytes]] = {}

        # The cipher object that was negotiated
        self.cipher_id = None

        # The signing algorithm that was negotiated
        self.signing_algorithm_id = None

        # Keep track of the message processing thread's potential traceback that it may raise.
        self._t_exc = None

        # The thread that will handle message processing.
        self._t_worker = None

    def connect(self, dialect=None, timeout=60, preferred_encryption_algos=None, preferred_signing_algos=None):
        """
        Will connect to the target server and negotiate the capabilities
        with the client. Once setup, the client MUST call the disconnect()
        function to close the listener thread. This function will populate
        various connection properties that denote the capabilities of the
        server.

        If no preferred encryption or signing algorithms are specified then
        all algorithms are offered during negotiation. Older dialects may not
        be offered if a custom encryption or signing algorithm list is
        specified without the algorithm required by that dialect.

        By default the following encryption algorithms are used:

            AES_128_GCM
            AES_128_CCM (required for SMB 3.0.x)
            AES_256_GCM
            AES_256_CCM

        By default the following signing algorithms are used:

            AES_GMAC
            AES_CMAC (required for SMB 3.0.x)
            HMAC_SHA256 (required for SMB 2.x)

        :param dialect: If specified, forces the dialect that is negotiated
            with the server, if not set, then the newest dialect supported by
            the server is used up to SMB 3.1.1
        :param timeout: The timeout in seconds to wait for the initial
            negotiation process to complete
        :param preferred_encryption_algos: A list of encryption algorithm ids
            in priority order from highest to lowest. See :class:`Ciphers` for
            a list of known identifiers.
        :param preferred_signing_algos: A list of signing algorithm ids in
            priority order from highest to lowest.
            See :class:`SigningAlgorithms` for a list of known identifiers.
        """
        log.info("Setting up transport connection")
        self.transport = Tcp(self.server_name, self.port, timeout)
        self.transport.connect()
        self._t_worker = threading.Thread(
            target=self._process_message_thread, name=f"msg_worker-{self.server_name}:{self.port}"
        )
        self._t_worker.daemon = True
        self._t_worker.start()

        log.info("Starting negotiation with SMB server")
        enc_algos = preferred_encryption_algos or [
            Ciphers.AES_128_GCM,
            Ciphers.AES_128_CCM,
            Ciphers.AES_256_GCM,
            Ciphers.AES_256_CCM,
        ]
        sign_algos = preferred_signing_algos or [
            SigningAlgorithms.AES_GMAC,
            SigningAlgorithms.AES_CMAC,
            SigningAlgorithms.HMAC_SHA256,
        ]
        smb_response = self._send_smb2_negotiate(dialect, timeout, enc_algos, sign_algos)
        log.info("Negotiated dialect: %s", smb_response["dialect_revision"])
        try:
            self._validate_negotiate_response(smb_response, enc_algos, sign_algos)
        except SMBException:
            self.disconnect(False)
            raise

        self.dialect = smb_response["dialect_revision"].get_value()
        self.max_transact_size = smb_response["max_transact_size"].get_value()
        self.max_read_size = smb_response["max_read_size"].get_value()
        self.max_write_size = smb_response["max_write_size"].get_value()
        self.server_guid = smb_response["server_guid"].get_value()
        self.gss_negotiate_token = smb_response["buffer"].get_value()

        # MS-SMB2 3.2.5.2 - RequireSigning is set when the server requires it. Connection.ClientSecurityMode must stay
        # as the value sent in the NEGOTIATE request as it is echoed back in VALIDATE_NEGOTIATE_INFO.
        if not self.require_signing and smb_response["security_mode"].has_flag(
            SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
        ):
            self.require_signing = True
        log.info("Connection require signing: %s", self.require_signing)

        capabilities = smb_response["capabilities"]
        self.server_capabilities = capabilities
        self.server_security_mode = smb_response["security_mode"].get_value()

        # SMB 2.1
        if self.dialect >= Dialects.SMB_2_1_0:
            self.supports_file_leasing = capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_LEASING)
            self.supports_multi_credit = capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_LARGE_MTU)

        # SMB 3.x
        if self.dialect >= Dialects.SMB_3_0_0:
            self.supports_directory_leasing = capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_DIRECTORY_LEASING)
            self.supports_multi_channel = capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL)

            # TODO: SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
            self.supports_persistent_handles = False
            self.supports_encryption = (
                capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION) and self.dialect < Dialects.SMB_3_1_1
            )

            # TODO: Check/add server to server_list in Client Page 203

        # SMB 3.1
        if self.dialect >= Dialects.SMB_3_1_1:
            for context in smb_response["negotiate_context_list"]:
                context_type = context["context_type"].get_value()

                if context_type == NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES:
                    self.cipher_id = context["data"]["ciphers"][0]
                    self.supports_encryption = self.cipher_id != 0

                elif context_type == NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
                    self.preauth_integrity_hash_id = context["data"]["hash_algorithms"][0]

                elif context_type == NegotiateContextType.SMB2_SIGNING_CAPABILITIES:
                    self.signing_algorithm_id = context["data"]["signing_algorithms"][0]

    def _validate_negotiate_response(self, smb_response, encryption_algorithms, signing_algorithms):
        """Validates the NEGOTIATE response as specified in MS-SMB2 3.2.5.2."""
        dialect = smb_response["dialect_revision"].get_value()
        if dialect not in self.negotiated_dialects:
            raise SMBException(
                f"Server selected dialect 0x{dialect:04X} that was not offered by the client: "
                f"{', '.join(f'0x{d:04X}' for d in self.negotiated_dialects)}"
            )

        if dialect < Dialects.SMB_3_1_1:
            return

        contexts = {}
        for context in smb_response["negotiate_context_list"]:
            contexts.setdefault(context["context_type"].get_value(), []).append(context)

        if len(contexts.get(NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, [])) != 1:
            raise SMBException(
                "Negotiate response must contain exactly one SMB2_PREAUTH_INTEGRITY_CAPABILITIES context"
            )

        for context_type in [
            NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES,
            NegotiateContextType.SMB2_COMPRESSION_CAPABILITIES,
            NegotiateContextType.SMB2_RDMA_TRANSFORM_CAPABILITIES,
            NegotiateContextType.SMB2_SIGNING_CAPABILITIES,
            NegotiateContextType.SMB2_TRANSPORT_CAPABILITIES,
        ]:
            if len(contexts.get(context_type, [])) > 1:
                raise SMBException(f"Negotiate response contains more than one context of type 0x{context_type:04X}")

        hash_algos = contexts[NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES][0]["data"]["hash_algorithms"]
        hash_algos = hash_algos.get_value()
        if len(hash_algos) != 1 or hash_algos[0] != HashAlgorithms.SHA_512:
            raise SMBException(f"Negotiate response contains an invalid preauth integrity hash algorithm {hash_algos}")

        for context in contexts.get(NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES, []):
            ciphers = context["data"]["ciphers"].get_value()
            if len(ciphers) != 1 or (ciphers[0] != 0 and ciphers[0] not in encryption_algorithms):
                raise SMBException(f"Negotiate response contains an invalid encryption cipher {ciphers}")

        for context in contexts.get(NegotiateContextType.SMB2_SIGNING_CAPABILITIES, []):
            signing = context["data"]["signing_algorithms"].get_value()
            if len(signing) != 1 or signing[0] not in signing_algorithms:
                raise SMBException(f"Negotiate response contains an invalid signing algorithm {signing}")

    def disconnect(self, close=True, timeout=None):
        """
        Closes the connection as well as logs off any of the
        Disconnects the TCP connection and shuts down the socket listener
        running in a thread.

        :param close: Will close all sessions in the connection as well as the
            tree connections of each session.
        """
        # We cannot close the session or tree if the socket has been closed.
        if close and self.transport.connected:
            for session in list(self.session_table.values()):
                session.disconnect(True, timeout=timeout)

        log.info("Disconnecting transport connection")
        self.transport.close()
        if self._t_worker and self._t_worker.ident != threading.get_ident():
            self._t_worker.join(timeout=2)

    def send(
        self, message, sid=None, tid=None, credit_request=None, message_id=None, async_id=None, force_signature=False
    ):
        """
        Will send a message to the server that is passed in. The final unencrypted header is returned to the function
        that called this.

        :param message: An SMB message structure to send.
        :param sid: A session_id that the message is sent for.
        :param tid: A tree_id object that the message is sent for.
        :param credit_request: Specifies extra credits to be requested with the SMB header.
        :param message_id: The message_id for the header, only useful for a cancel request.
        :param async_id: The async_id for the header, only useful for a cancel request.
        :param force_signature: Force signing the SMB request even if not requested by the client/server.
        :return: Request of the message that was sent.
        """
        return self._send(
            [message],
            session_id=sid,
            tree_id=tid,
            message_id=message_id,
            credit_request=credit_request,
            async_id=async_id,
            force_signature=force_signature,
        )[0]

    def send_compound(self, messages, sid, tid, related=False):
        """
        Sends multiple messages within 1 TCP request, will fail if the size of the total length exceeds the maximum of
        the transport max.

        :param messages: A list of messages to send to the server.
        :param sid: The session_id that the request is sent for.
        :param tid: A tree_id object that the message is sent for.
        :param related: Whether each message is related to each other, sets the Session, Tree, and File Id to the same
            value as the first message.
        :return: List<Request> for each request that was sent, each entry in the list is in the same order of the
            message list that was passed in.
        """
        return self._send(messages, session_id=sid, tree_id=tid, related=related)

    def receive(self, request, wait=True, timeout=None, resolve_symlinks=True):
        """
        Polls the message buffer of the TCP connection and waits until a valid
        message is received based on the message_id passed in.

        :param request: The Request object to wait get the response for
        :param wait: Wait for the final response in the case of a STATUS_PENDING response, the pending response is
            returned in the case of wait=False
        :param timeout: Set a timeout used while waiting for the final response from the server.
        :param resolve_symlinks: Set to automatically resolve symlinks in the path when opening a file or directory.
        :return: SMB2HeaderResponse of the received message
        """
        # Only the worker thread delivers responses, so calling receive() from it would wait
        # on an event only it can set.
        worker = self._t_worker
        if worker is not None and threading.get_ident() == worker.ident:
            raise SMBException("Connection.receive() called from the SMB worker thread, would self-deadlock")

        # Make sure the receiver is still active, if not this raises an exception.
        self._check_worker_running()

        start_time = time.time()
        while True:
            iter_timeout = int(max(timeout - (time.time() - start_time), 1)) if timeout is not None else None
            if not request.response_event.wait(timeout=iter_timeout):
                value = request.message["message_id"].get_value()
                raise SMBException(
                    f"Connection timeout of {timeout} seconds exceeded while waiting for a message id {value} "
                    "response from the server"
                )

            # Use a lock on the request so that in the case of a pending response we have exclusive lock on the event
            # flag and can clear it without the future pending response taking it over before we first clear the flag.
            with request.response_event_lock:
                self._check_worker_running()  # The worker may have failed while waiting for the response, check again

                response = request.response
                status = response["status"].get_value()
                if status == NtStatus.STATUS_PENDING:
                    if not wait:
                        # Keep the request in outstanding_requests so the final response can still be matched to it.
                        break

                    # Received a pending message, clear the response_event flag and wait again.
                    request.response_event.clear()
                    continue
                elif status == NtStatus.STATUS_STOPPED_ON_SYMLINK and resolve_symlinks:
                    # Received when we do an Open on a path that contains a symlink. Need to capture all related
                    # requests and resend the Open + others with the redirected path. First we need to resolve the
                    # symlink path. This will fail if the symlink is pointing to a location that is not in the same
                    # tree/share as the original request.

                    # First wait for the other remaining requests to be processed. Their status will also fail and we
                    # need to make sure we update the old request with the new one properly.
                    related_requests = [self.outstanding_requests[i] for i in request.related_ids]
                    [r.response_event.wait() for r in related_requests]

                    # Check if the response has the reparse buffer present.
                    exp = SMBResponseException(response)
                    reparse_buffer = next(
                        iter(e for e in exp.error_details if isinstance(e, SMB2SymbolicLinkErrorResponse)), None
                    )
                    if reparse_buffer is None:
                        # Some SMB server don't return a buffer, only thing we
                        # can do is raise the exception.
                        message_id = request.message["message_id"].get_value()
                        self.outstanding_requests.pop(message_id, None)
                        raise exp

                    # Now create a new request with the new path the symlink points to.
                    session = self.session_table[request.session_id]
                    tree = session.tree_connect_table[request.message["tree_id"].get_value()]

                    old_create = request.get_message_data()
                    create_path = to_text(old_create["buffer_path"].get_value(), encoding="utf-16-le")
                    if tree.is_dfs_share:
                        # MS-SMB2 3.2.4.3 - CREATE paths on a DFS share are already DFS pathnames in the form
                        # server\share\path and the redirected path must be sent in the same form.
                        new_path = reparse_buffer.resolve_path("\\\\" + create_path)[2:]
                    else:
                        tree_share_name = tree.share_name + "\\"
                        new_path = reparse_buffer.resolve_path(tree_share_name + create_path)[len(tree_share_name) :]

                    new_open = Open(tree, new_path)
                    create_req = new_open.create(
                        old_create["impersonation_level"].get_value(),
                        old_create["desired_access"].get_value(),
                        old_create["file_attributes"].get_value(),
                        old_create["share_access"].get_value(),
                        old_create["create_disposition"].get_value(),
                        old_create["create_options"].get_value(),
                        create_contexts=old_create["buffer_contexts"].get_value(),
                        send=False,
                    )[0]

                    # Now add all the related requests (if any) to send as a compound request.
                    new_msgs = [create_req] + [r.get_message_data() for r in related_requests]
                    new_requests = self.send_compound(new_msgs, session.session_id, tree.tree_connect_id, related=True)

                    # Verify that the first request was successful before updating the related requests with the new
                    # info.
                    error = None
                    try:
                        new_response = self.receive(new_requests[0], wait=wait, timeout=timeout, resolve_symlinks=True)
                    except SMBResponseException as exc:
                        # We need to make sure we fix up the remaining responses before throwing this.
                        error = exc
                    [r.response_event.wait() for r in new_requests]

                    # Update the old requests with the new response information
                    for i, old_request in enumerate([request] + related_requests):
                        del self.outstanding_requests[old_request.message["message_id"].get_value()]
                        old_request.update_request(new_requests[i])

                    if error:
                        raise error

                    return new_response
                else:
                    # now we have a retrieval request for the response, we can delete
                    # the request from the outstanding requests
                    message_id = request.message["message_id"].get_value()
                    self.outstanding_requests.pop(message_id, None)

                    # MS-SMB2 3.3.4.4 - STATUS_BUFFER_OVERFLOW is a warning for these commands and the response
                    # contains valid, truncated data that must be returned to the caller.
                    is_buffer_overflow = (
                        status == NtStatus.STATUS_BUFFER_OVERFLOW
                        and response["command"].get_value() in self._BUFFER_OVERFLOW_COMMANDS
                    )
                    if status != NtStatus.STATUS_SUCCESS and not is_buffer_overflow:
                        raise SMBResponseException(response)

                    break

        return response

    def echo(self, sid=0, timeout=60, credit_request=1):
        """
        Sends an SMB2 Echo request to the server. This can be used to request
        more credits from the server with the credit_request param.

        On a Samba server, the sid can be 0 but for a Windows SMB Server, the
        sid of an authenticated session must be passed into this function or
        else the socket will close.

        :param sid: When talking to a Windows host this must be populated with
            a valid session_id from a negotiated session
        :param timeout: The timeout in seconds to wait for the Echo Response
        :param credit_request: The number of credits to request
        :return: the credits that were granted by the server
        """
        log.info("Sending Echo request with a timeout of %d and credit request of %d" % (timeout, credit_request))

        echo_msg = SMB2Echo()
        log.debug(echo_msg)
        req = self.send(echo_msg, sid=sid, credit_request=credit_request)

        log.info("Receiving Echo response")
        response = self.receive(req, timeout=timeout)
        log.info("Credits granted from the server echo response: %d" % response["credit_response"].get_value())
        echo_resp = SMB2Echo()
        echo_resp.unpack(response["data"].get_value())
        log.debug(echo_resp)

        return response["credit_response"].get_value()

    def verify_signature(self, header, session_id, force=False, b_header=None):
        """
        Verifies the SMB2 Header request/response signature.

        The signature of a signed message is always verified. When the session requires signing (or force is set), a
        message without SMB2_FLAGS_SIGNED is rejected as the flag itself is not protected and could have been
        cleared by an attacker. MS-SMB2 3.2.5.1.3 only allows the verification to be skipped for decrypted messages,
        unsolicited messages with the MessageId 0xFFFFFFFFFFFFFFFF, and interim STATUS_PENDING responses.

        :param header: The SMB2Header that will have its signature verified against the signing key specified.
        :param session_id: The Session Id to denote what session security verifies the message.
        :param force: Force verification of the header even if it does not match the criteria required in normal
            scenarios.
        :param b_header: The raw bytes the header was unpacked from, avoids packing the message again when set.
        :return: True if the signature was verified, False if no verification was required.
        """
        message_id = header["message_id"].get_value()
        flags = header["flags"]
        status = header["status"].get_value()
        command = header["command"].get_value()

        if not force and (
            message_id == 0xFFFFFFFFFFFFFFFF
            or status == NtStatus.STATUS_PENDING
            or command == Commands.SMB2_SESSION_SETUP
        ):
            return False

        is_signed = flags.has_flag(Smb2Flags.SMB2_FLAGS_SIGNED)
        session = self.session_table.get(session_id, None)
        if session is None:
            if not is_signed and not force:
                # Messages outside of an authenticated session, like NEGOTIATE, are never signed.
                return False

            raise SMBException(f"Failed to find session {session_id} for message verification")

        if not is_signed:
            signing_required = session.signing_required and session.signing_key
            if not force and (not signing_required or status in self._UNSIGNED_ERROR_STATUSES):
                return False

            raise SMBException(
                f"Server message for session {session_id} with message id {message_id} was not signed but "
                "signing is required"
            )

        expected = self._generate_signature(
            header.pack() if b_header is None else b_header,
            session.signing_key,
            message_id,
            flags.has_flag(Smb2Flags.SMB2_FLAGS_SERVER_TO_REDIR),
            command,
        )
        actual = header["signature"].get_value()
        if actual != expected:
            actual_signature = binascii.hexlify(actual).decode()
            expected_signature = binascii.hexlify(expected).decode()
            raise SMBException(
                f"Server message signature could not be verified: {actual_signature} != {expected_signature}",
            )

        return True

    def _wait_for_credits(self, required, unsent=(), timeout=None):
        """
        Waits until the sequence window has the required number of message ids available. Must be called with
        sequence_lock held.

        If no responses are outstanding then no more credits can be granted by the server so the request fails
        immediately rather than waiting forever.

        :param required: The number of credits the request needs.
        :param unsent: Requests that have been created but not sent yet, these will not grant any credits.
        :param timeout: Override the time in seconds to wait for credits, defaults to the receive timeout.
        """
        timeout = self._receive_timeout if timeout is None else timeout
        worker = self._t_worker
        if worker is not None and threading.get_ident() == worker.ident:
            # Only the worker thread processes credit grants so it cannot wait for them.
            timeout = 0
        end_time = time.monotonic() + timeout
        while True:
            available = self.sequence_window["high"] - self.sequence_window["low"]
            if required <= available:
                return

            credits_pending = any(
                r.response is None or r.response["status"].get_value() == NtStatus.STATUS_PENDING
                for r in list(self.outstanding_requests.values())
                if not any(r is u for u in unsent)
            )
            remaining = end_time - time.monotonic()
            if not credits_pending or remaining <= 0 or self._t_exc is not None or not self.transport.connected:
                raise SMBException(f"Request requires {required} credits but only {available} credits are available")

            self._credits_granted.wait(timeout=remaining)

    def _check_worker_running(self):
        """Checks that the message worker thread is still running and raises it's exception if it has failed."""
        if self._t_exc is not None:
            self.disconnect(False)
            raise self._t_exc

        elif not self.transport.connected:
            raise SMBConnectionClosed("SMB socket was closed, cannot send or receive any more data")

    def _send(
        self,
        messages,
        session_id=None,
        tree_id=None,
        message_id=None,
        credit_request=None,
        related=False,
        async_id=None,
        force_signature=False,
    ):
        send_parts = []
        requests = []
        session = self.session_table.get(session_id, None)
        tree = None
        is_dfs = False
        if tree_id and session:
            if tree_id not in session.tree_connect_table:
                raise SMBException("Cannot find Tree with the ID %d in the session tree table" % tree_id)
            tree = session.tree_connect_table[tree_id]
            is_dfs = tree.is_dfs_share

        total_requests = len(messages)
        for i, message in enumerate(messages):
            if i == total_requests - 1:
                next_command = 0
                padding = b""
            else:
                # each compound message must start at the 8-byte boundary
                msg_length = 64 + len(message)
                mod = msg_length % 8
                padding_length = 8 - mod if mod > 0 else 0
                next_command = msg_length + padding_length
                padding = b"\x00" * padding_length

            # When running with multiple threads we need to ensure that getting the message id and adjusting the
            # sequence windows is done in a thread safe manner so we use a lock to ensure only 1 thread accesses the
            # sequence window at a time.
            with self.sequence_lock:
                credit_charge = self._calculate_credit_charge(message)
                if message.COMMAND == Commands.SMB2_CANCEL:
                    # MS-SMB2 3.2.4.24 - CANCEL does not consume a message id.
                    current_id = message_id
                else:
                    # MS-SMB2 3.2.4.1.3 - a request that requires more message ids than are available must wait.
                    self._wait_for_credits(max(credit_charge, 1), unsent=requests)
                    current_id = message_id or self.sequence_window["low"]
                    self.sequence_window["low"] += max(credit_charge, 1)

            if async_id is None:
                header = SMB2HeaderRequest()
                header["tree_id"] = tree_id or 0
            else:
                header = SMB2HeaderAsync()
                header["flags"].set_flag(Smb2Flags.SMB2_FLAGS_ASYNC_COMMAND)
                header["async_id"] = async_id

            msg_credit_request = credit_request
            if msg_credit_request is None:
                # MS-SMB2 3.2.4.1.2 - request at least the credits consumed so the client never runs out of credits.
                msg_credit_request = 0 if message.COMMAND == Commands.SMB2_CANCEL else max(credit_charge, 1)

            header["credit_charge"] = credit_charge
            header["command"] = message.COMMAND
            header["credit_request"] = msg_credit_request
            header["message_id"] = current_id
            header["session_id"] = session_id
            header["data"] = message.pack()
            header["next_command"] = next_command

            if is_dfs:
                header["flags"].set_flag(Smb2Flags.SMB2_FLAGS_DFS_OPERATIONS)

            if i != 0 and related:
                header["flags"].set_flag(Smb2Flags.SMB2_FLAGS_RELATED_OPERATIONS)

            # The header and the message data are kept separate until the final join so the data, which can be
            # multiple MiB for a READ response or WRITE request, is copied only once.
            sign = force_signature or (session and session.signing_required and session.signing_key)
            if sign:
                header["flags"].set_flag(Smb2Flags.SMB2_FLAGS_SIGNED)

            b_fixed = b"".join(field.pack() for name, field in header.fields.items() if name != "data")
            b_data = header["data"].get_value()
            if sign:
                signature = self._calculate_signature(
                    (memoryview(b_fixed)[:48], b"\x00" * 16, b_data, padding),
                    session.signing_key,
                    current_id,
                    False,
                    message.COMMAND,
                )
                header["signature"] = signature
                b_header = b"".join((b_fixed[:48], signature, b_data, padding))
            else:
                b_header = b"".join((b_fixed, b_data, padding))

            send_parts.append(b_header)

            if message.COMMAND == Commands.SMB2_CANCEL:
                # The request being cancelled may have already been completed and removed.
                request = self.outstanding_requests.get(header["message_id"].get_value(), None)
            else:
                request = Request(header, type(message), self, session_id=session_id)
                self.outstanding_requests[header["message_id"].get_value()] = request

            # Make sure the preauth integrity values are updated for a negotiate or session setup message.
            if message.COMMAND == Commands.SMB2_NEGOTIATE:
                self.preauth_integrity_hash_value.append(b_header)

            elif message.COMMAND == Commands.SMB2_SESSION_SETUP:
                self.preauth_integrity_session_hash_value[current_id] = [b_header]

            requests.append(request)

        if related:
            requests[0].related_ids = [r.message["message_id"].get_value() for r in requests][1:]

        send_data = b"".join(send_parts)
        if session and session.encrypt_data or tree and tree.encrypt_data:
            send_data = self._encrypt(send_data, session)

        self._check_worker_running()
        self.transport.send(send_data)
        return requests

    def _process_message_thread(self):
        try:
            while True:
                # Wait for a max of 10 minutes before sending an echo that tells the SMB server the client is still
                # available. This stops the server from closing the connection and the associated sessions on a long
                # lived connection. A brief test shows Windows kills a connection at ~16 minutes so 10 minutes is a
                # safe choice.
                # https://github.com/jborean93/smbprotocol/issues/31
                try:
                    b_msg = self.transport.recv(self._receive_timeout)
                except TimeoutError as ex:
                    # Check if the connection has unanswered keepalive echo requests with the reserved field set.
                    # When unanswered keep alive echo exists, the server did not respond withing two times the timeout.
                    # We assume that the server connection is dead and close it.
                    for r in self.outstanding_requests.values():
                        if (
                            r.response is None
                            and r.message["command"].get_value() == Commands.SMB2_ECHO
                            and r.message["reserved"].get_value() == 1
                        ):
                            # connection will be closed in finally block
                            raise SMBConnectionClosed(
                                "Connection timed out. Server did not respond within timeout."
                            ) from ex

                    log.debug("Sending SMB2 Echo to keep connection alive")
                    for sid in self.session_table.keys():
                        req = self.send(SMB2Echo(), sid=sid)
                        # Set this reserved field to 1 as we use that internally to check whether the outstanding
                        # requests queue should be cleared in this thread or not.
                        req.message["reserved"] = 1
                    continue

                # If recv didn't return any data then the socket is considered to be closed.
                if not b_msg:
                    return

                is_encrypted = b_msg[:4] == b"\xfdSMB"
                transform_session_id = None
                if is_encrypted:
                    msg = SMB2TransformHeader()
                    msg.unpack(b_msg)
                    b_msg = self._decrypt(msg)
                    transform_session_id = msg["session_id"].get_value()

                # MS-SMB2 3.2.5.1 and 3.2.5.1.1.1 - only plain SMB2 messages are expected at this point, compression is
                # never negotiated and an encrypted message must not contain another transform header.
                if b_msg[:4] != b"\xfeSMB":
                    raise SMBException(f"Received message with an unknown or unexpected ProtocolId {b_msg[:4]!r}")

                is_first = True
                next_command = -1
                while next_command != 0:
                    next_command = struct.unpack("<L", b_msg[20:24])[0]
                    if next_command % 8 != 0:
                        # MS-SMB2 3.2.5.1.9 - each compounded response must start on an 8-byte boundary.
                        raise SMBException(f"Compounded response NextCommand {next_command} is not 8-byte aligned")

                    header_length = next_command if next_command != 0 else len(b_msg)
                    b_header = b_msg[:header_length]
                    b_msg = b_msg[header_length:]

                    header = SMB2HeaderResponse()
                    header.unpack(b_header)

                    if (
                        is_encrypted
                        and header["session_id"].get_value() != transform_session_id
                        and (is_first or not header["flags"].has_flag(Smb2Flags.SMB2_FLAGS_RELATED_OPERATIONS))
                    ):
                        # MS-SMB2 3.2.5.1.1.1 - the decrypted message must belong to the session it was encrypted for.
                        raise SMBException(
                            f"Decrypted message SessionId {header['session_id'].get_value()} does not match the "
                            f"transform header SessionId {transform_session_id}"
                        )
                    is_first = False

                    message_id = header["message_id"].get_value()
                    command = header["command"].get_value()
                    if message_id == 0xFFFFFFFFFFFFFFFF:
                        # MS-SMB2 3.2.5.1.2 - an unsolicited message, only an OPLOCK_BREAK is valid.
                        if command == Commands.SMB2_OPLOCK_BREAK:
                            self._process_break_notification(header)
                        else:
                            log.warning("Discarding unsolicited message with command %s", command)
                        continue

                    request = self.outstanding_requests.get(message_id, None)
                    if request is None:
                        # MS-SMB2 3.2.5.1.2 - a response that does not match a request must be discarded.
                        log.warning("Discarding response for unknown message id %s", message_id)
                        continue

                    # For SMB2 SESSION_SETUP, the client MUST retrieve SessionId
                    # from SMB2 header of the response. For all other messages,
                    # the client MUST retrieve SessionId from the corresponding
                    # Request.Message.
                    if command == Commands.SMB2_SESSION_SETUP:
                        session_id = header["session_id"].get_value()
                    else:
                        session_id = request.session_id

                    # No need to waste CPU cycles to verify the signature if we already decrypted the header.
                    signature_verified = False
                    if not is_encrypted:
                        signature_verified = self.verify_signature(header, session_id, b_header=b_header)

                    credit_response = header["credit_response"].get_value()
                    with self.sequence_lock:
                        self.sequence_window["high"] += credit_response
                        self._credits_granted.notify_all()

                    status = header["status"].get_value()
                    if command == Commands.SMB2_NEGOTIATE:
                        self.preauth_integrity_hash_value.append(b_header)

                    elif command == Commands.SMB2_SESSION_SETUP and status == NtStatus.STATUS_MORE_PROCESSING_REQUIRED:
                        self.preauth_integrity_session_hash_value[message_id].append(b_header)

                    with request.response_event_lock:
                        if header["flags"].has_flag(Smb2Flags.SMB2_FLAGS_ASYNC_COMMAND):
                            request.async_id = b_header[32:40]

                        request.response = header
                        request.response_encrypted = is_encrypted
                        request.response_signature_verified = signature_verified
                        request.response_event.set()

                        # When we send a ping or break acknowledgment in this thread we want to make sure it doesn't
                        # linger in the outstanding request queue.
                        if status != NtStatus.STATUS_PENDING and (
                            request.message["reserved"].get_value() == 1 or request.on_response is not None
                        ):
                            self.outstanding_requests.pop(message_id, None)

                    if request.on_response is not None and status != NtStatus.STATUS_PENDING:
                        request.on_response(header)
        except Exception as exc:
            log.exception("SMB receive worker died (outstanding=%d)", len(self.outstanding_requests))

            # The exception is raised in _check_worker_running by the caller thread when send/receive is called next.
            self._t_exc = exc

            # While a caller of send/receive could theoretically catch this exception, we consider any failures
            # here a fatal errors and the connection should be closed so we exit the worker thread.
            self.disconnect(False)

        finally:
            # Make sure we fire all the request events to ensure the main thread isn't waiting on a receive.
            for request in list(self.outstanding_requests.values()):
                request.response_event.set()

            # Also wake up any request waiting for credits that will now never be granted.
            with self.sequence_lock:
                self._credits_granted.notify_all()

    def _find_open(self, file_id):
        for session in list(self.session_table.values()):
            smb_open = session.open_table.get(file_id, None)
            if smb_open is not None:
                return smb_open

        return None

    def _process_break_notification(self, header):
        """
        [MS-SMB2] 3.2.5.19 Receiving an SMB2 OPLOCK_BREAK Command

        Processes an unsolicited oplock or lease break notification. The library does not cache any data locally so
        the break is acknowledged straight away with the new oplock level or lease state.
        """
        data = header["data"].get_value()
        structure_size = struct.unpack("<H", data[:2])[0] if len(data) >= 2 else 0

        if structure_size == 24:
            notification = SMB2OplockBreakNotification()
            notification.unpack(data)
            self._process_oplock_break(notification)

        elif (
            structure_size == 44
            and self.dialect != Dialects.SMB_2_0_2
            and (self.supports_file_leasing or self.supports_directory_leasing)
        ):
            notification = SMB2LeaseBreakNotification()
            notification.unpack(data)
            self._process_lease_break(notification)

        else:
            log.warning("Discarding OPLOCK_BREAK notification with unexpected StructureSize %d", structure_size)

    def _process_oplock_break(self, notification):
        smb_open = self._find_open(notification["file_id"].get_value())
        if smb_open is None:
            return

        current_level = smb_open.oplock_level
        new_level = notification["oplock_level"].get_value()
        log.info("Received oplock break for %s from %s to %s", smb_open.file_name, current_level, new_level)

        if current_level == RequestedOplockLevel.SMB2_OPLOCK_LEVEL_II:
            if new_level == RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE:
                smb_open.oplock_level = new_level
            return

        valid_levels = {
            RequestedOplockLevel.SMB2_OPLOCK_LEVEL_EXCLUSIVE: [
                RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE,
                RequestedOplockLevel.SMB2_OPLOCK_LEVEL_II,
            ],
            RequestedOplockLevel.SMB2_OPLOCK_LEVEL_BATCH: [
                RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE,
                RequestedOplockLevel.SMB2_OPLOCK_LEVEL_II,
                RequestedOplockLevel.SMB2_OPLOCK_LEVEL_EXCLUSIVE,
            ],
        }.get(current_level, [])
        if new_level not in valid_levels:
            return

        smb_open.oplock_level = new_level
        ack = SMB2OplockBreakAcknowledgment()
        ack["oplock_level"] = new_level
        ack["file_id"] = smb_open.file_id

        def on_response(response):
            # MS-SMB2 3.2.5.19.3
            if response["status"].get_value() != NtStatus.STATUS_SUCCESS:
                smb_open.oplock_level = RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE

        self._send_break_acknowledgment(ack, smb_open, on_response)

    def _process_lease_break(self, notification):
        lease_key = notification["lease_key"].get_value()
        opens = [
            o
            for session in list(self.session_table.values())
            for o in list(session.open_table.values())
            if o.lease_key == lease_key
        ]
        if not opens:
            return

        new_state = notification["new_lease_state"].get_value()
        new_epoch = notification["new_epoch"].get_value()
        log.info("Received lease break for %s to state %d", opens[0].file_name, new_state)
        for smb_open in opens:
            if self.dialect >= Dialects.SMB_3_0_0 and smb_open.lease_epoch is not None:
                if new_epoch != smb_open.lease_epoch and ((new_epoch - smb_open.lease_epoch) & 0xFFFF) <= 32767:
                    smb_open.lease_state = new_state
                    smb_open.lease_epoch = new_epoch
            else:
                smb_open.lease_state = new_state

        if not notification["flags"].has_flag(LeaseBreakFlags.SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED):
            return

        ack = SMB2LeaseBreakAcknowledgment()
        ack["lease_key"] = lease_key
        ack["lease_state"] = opens[0].lease_state

        def on_response(response):
            # MS-SMB2 3.2.5.19.4
            if response["status"].get_value() != NtStatus.STATUS_SUCCESS:
                for smb_open in opens:
                    smb_open.lease_state = 0
                    smb_open.oplock_level = RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE

        self._send_break_acknowledgment(ack, opens[0], on_response)

    def _send_break_acknowledgment(self, message, smb_open, on_response):
        try:
            request = self.send(
                message,
                sid=smb_open.tree_connect.session.session_id,
                tid=smb_open.tree_connect.tree_connect_id,
            )
        except SMBException as exc:
            log.warning("Failed to send oplock break acknowledgment for %s: %s", smb_open.file_name, exc)
            return

        # The response is processed by this worker thread as nothing else waits for it.
        request.on_response = on_response

    def _generate_signature(self, b_header, signing_key, message_id, response, command):
        # The signature is calculated over the message with the signature field zeroed. Pass the message in pieces so a
        # large message is not copied just to blank 16 bytes.
        view = memoryview(b_header)
        return self._calculate_signature(
            (view[:48], b"\x00" * 16, view[64:]), signing_key, message_id, response, command
        )

    def _calculate_signature(self, parts, signing_key, message_id, response, command):
        """Signs the concatenation of the bytes-like objects in parts, the signature field must already be zeroed."""
        if self.dialect >= Dialects.SMB_3_1_1 and self.signing_algorithm_id is not None:
            sign_id = self.signing_algorithm_id

        elif self.dialect >= Dialects.SMB_3_0_0:
            sign_id = SigningAlgorithms.AES_CMAC

        else:
            sign_id = SigningAlgorithms.HMAC_SHA256

        if sign_id == SigningAlgorithms.AES_GMAC:
            message_info = 0
            if response:
                message_info |= 1

            if command == Commands.SMB2_CANCEL:
                message_info |= 2

            nonce = b"".join(
                [
                    message_id.to_bytes(8, byteorder="little"),
                    message_info.to_bytes(4, byteorder="little"),
                ]
            )
            # GMAC is AES-GCM over no plaintext with the message as the additional data.
            encryptor = Cipher(algorithms.AES(signing_key), modes.GCM(nonce), backend=default_backend()).encryptor()
            for part in parts:
                encryptor.authenticate_additional_data(part)
            encryptor.finalize()
            signature = encryptor.tag

        elif sign_id == SigningAlgorithms.AES_CMAC:
            c = cmac.CMAC(algorithms.AES(signing_key), backend=default_backend())
            for part in parts:
                c.update(part)
            signature = c.finalize()

        else:
            hmac_algo = hmac.new(signing_key, digestmod=hashlib.sha256)
            for part in parts:
                hmac_algo.update(part)
            signature = hmac_algo.digest()[:16]

        return signature

    def _encrypt(self, b_data, session):
        header = SMB2TransformHeader()
        header["original_message_size"] = len(b_data)
        header["session_id"] = session.session_id

        encryption_key = session.encryption_key
        if self.dialect >= Dialects.SMB_3_1_1:
            cipher_id = self.cipher_id
        else:
            cipher_id = Ciphers.AES_128_CCM

        if cipher_id in [Ciphers.AES_128_GCM, Ciphers.AES_256_GCM]:
            cipher = aead.AESGCM
            nonce = os.urandom(12)
            header["nonce"] = nonce + (b"\x00" * 4)
        else:
            cipher = aead.AESCCM
            nonce = os.urandom(11)
            header["nonce"] = nonce + (b"\x00" * 5)

        cipher_text = cipher(encryption_key).encrypt(nonce, b_data, header.pack()[20:])
        signature = cipher_text[-16:]
        enc_message = cipher_text[:-16]

        header["signature"] = signature
        header["data"] = enc_message

        return header

    def _decrypt(self, message):
        value = message["flags"].get_value()
        if value != 0x0001:
            error_msg = f"Expecting flag of 0x0001 but got {value:x} in the SMB Transform Header Response"
            raise SMBException(error_msg)

        session_id = message["session_id"].get_value()
        session = self.session_table.get(session_id, None)
        if session is None:
            raise SMBException(f"Failed to find valid session {session_id} for message decryption")

        if self.dialect >= Dialects.SMB_3_1_1:
            cipher_id = self.cipher_id
        else:
            cipher_id = Ciphers.AES_128_CCM

        if cipher_id in [Ciphers.AES_128_GCM, Ciphers.AES_256_GCM]:
            cipher = aead.AESGCM
            nonce_length = 12
        else:
            cipher = aead.AESCCM
            nonce_length = 11

        nonce = message["nonce"].get_value()[:nonce_length]
        signature = message["signature"].get_value()
        enc_message = message["data"].get_value() + signature

        c = cipher(session.decryption_key)
        # The AAD is the transform header from the Nonce field onwards (MS-SMB2 3.1.4.3), without the encrypted data.
        aad = b"".join(
            message[name].pack() for name in ("nonce", "original_message_size", "reserved", "flags", "session_id")
        )
        dec_message = c.decrypt(nonce, enc_message, aad)
        return dec_message

    def _send_smb2_negotiate(self, dialect, timeout, encryption_algorithms, signing_algorithms):
        self.salt = os.urandom(32)

        if dialect is None:
            neg_req = SMB3NegotiateRequest()
            negotiated_dialects = [
                Dialects.SMB_2_0_2,
                Dialects.SMB_2_1_0,
                Dialects.SMB_3_0_0,
                Dialects.SMB_3_0_2,
                Dialects.SMB_3_1_1,
            ]

            if SigningAlgorithms.HMAC_SHA256 not in signing_algorithms:
                if Dialects.SMB_2_0_2 in negotiated_dialects:
                    negotiated_dialects.remove(Dialects.SMB_2_0_2)
                if Dialects.SMB_2_1_0 in negotiated_dialects:
                    negotiated_dialects.remove(Dialects.SMB_2_1_0)

            if SigningAlgorithms.AES_CMAC not in signing_algorithms or Ciphers.AES_128_CCM not in encryption_algorithms:
                if Dialects.SMB_3_0_0 in negotiated_dialects:
                    negotiated_dialects.remove(Dialects.SMB_3_0_0)
                if Dialects.SMB_3_0_2 in negotiated_dialects:
                    negotiated_dialects.remove(Dialects.SMB_3_0_2)
        else:
            if dialect >= Dialects.SMB_3_1_1:
                neg_req = SMB3NegotiateRequest()
            else:
                neg_req = SMB2NegotiateRequest()
            negotiated_dialects = [dialect]

        highest_dialect = sorted(negotiated_dialects)[-1]
        self.negotiated_dialects = neg_req["dialects"] = negotiated_dialects
        log.info(
            "Negotiating with SMB2 protocol with highest client dialect of: %s",
            [dialect for dialect, v in vars(Dialects).items() if v == highest_dialect][0],
        )

        neg_req["security_mode"] = self.client_security_mode

        if highest_dialect >= Dialects.SMB_2_1_0:
            log.debug("Adding client guid %s to negotiate request", self.client_guid)
            neg_req["client_guid"] = self.client_guid

        else:
            # Must be None, this value is used to verify the negotiation info.
            self.client_guid = None

        if highest_dialect >= Dialects.SMB_3_0_0:
            log.debug("Adding client capabilities %d to negotiate request", self.client_capabilities)
            neg_req["capabilities"] = self.client_capabilities

        else:
            # Must be 0, this value is used to verify the negotiation info.
            self.client_capabilities = 0

        if highest_dialect >= Dialects.SMB_3_1_1:
            int_cap = SMB2NegotiateContextRequest()
            int_cap["context_type"] = NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            int_cap["data"] = SMB2PreauthIntegrityCapabilities()
            int_cap["data"]["hash_algorithms"] = [HashAlgorithms.SHA_512]
            int_cap["data"]["salt"] = self.salt
            log.debug(
                "Adding preauth integrity capabilities of hash SHA512 and salt %s to negotiate request",
                self.salt,
            )

            enc_cap = SMB2NegotiateContextRequest()
            enc_cap["context_type"] = NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
            enc_cap["data"] = SMB2EncryptionCapabilities()
            supported_ciphers = encryption_algorithms
            enc_cap["data"]["ciphers"] = supported_ciphers
            log.debug("Adding encryption capabilities of AES128|256 GCM and AES128|256 CCM to negotiate request")

            netname_id = SMB2NegotiateContextRequest()
            netname_id["context_type"] = NegotiateContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
            netname_id["data"] = SMB2NetnameNegotiateContextId()
            netname_id["data"]["net_name"] = self.server_name
            log.debug(f"Adding netname context id of {self.server_name} to negotiate request")

            signing_cap = SMB2NegotiateContextRequest()
            signing_cap["context_type"] = NegotiateContextType.SMB2_SIGNING_CAPABILITIES
            signing_cap["data"] = SMB2SigningCapabilities()
            signing_cap["data"]["signing_algorithms"] = signing_algorithms
            log.debug("Adding signing algorithms AES_GMAC, AES_CMAC, and HMAC_SHA256 to negotiate request")

            # remove extra padding for last list entry
            signing_cap["padding"].size = 0
            signing_cap["padding"] = b""

            neg_req["negotiate_context_list"] = [
                int_cap,
                enc_cap,
                netname_id,
                signing_cap,
            ]

        log.info("Sending SMB2 Negotiate message")
        log.debug(neg_req)
        request = self.send(neg_req)

        response = self.receive(request, timeout=timeout)
        log.info("Receiving SMB2 Negotiate response")
        log.debug(response)

        smb_response = SMB2NegotiateResponse()
        smb_response.unpack(response["data"].get_value())

        return smb_response

    def _calculate_credit_charge(self, message):
        """
        Calculates the credit charge for a request based on the command. If
        connection.supports_multi_credit is not True then the credit charge
        isn't valid so it returns 0.

        The credit charge is the number of credits that are required for
        sending/receiving data over 64 kilobytes, in the existing messages only
        the Read, Write, Query Directory or IOCTL commands will end in this
        scenario and each require their own calculation to get the proper
        value. The generic formula for calculating the credit charge is

        https://msdn.microsoft.com/en-us/library/dn529312.aspx
        (max(SendPayloadSize, Expected ResponsePayloadSize) - 1) / 65536 + 1

        :param message: The message being sent
        :return: The credit charge to set on the header
        """
        if (not self.supports_multi_credit) or (message.COMMAND == Commands.SMB2_CANCEL):
            return 0

        elif message.COMMAND == Commands.SMB2_READ:
            payload_size = message["length"].get_value() + message["read_channel_info_length"].get_value()

        elif message.COMMAND == Commands.SMB2_WRITE:
            payload_size = message["length"].get_value() + message["write_channel_info_length"].get_value()

        elif message.COMMAND == Commands.SMB2_IOCTL:
            max_in_size = len(message["buffer"])
            max_out_size = message["max_output_response"].get_value()
            payload_size = max(max_in_size, max_out_size)

        elif message.COMMAND == Commands.SMB2_QUERY_DIRECTORY:
            max_in_size = len(message["buffer"])
            max_out_size = message["output_buffer_length"].get_value()
            payload_size = max(max_in_size, max_out_size)

        elif message.COMMAND == Commands.SMB2_QUERY_INFO:
            max_in_size = message["input_buffer_length"].get_value()
            max_out_size = message["output_buffer_length"].get_value()
            payload_size = max(max_in_size, max_out_size)

        elif message.COMMAND == Commands.SMB2_SET_INFO:
            payload_size = message["buffer_length"].get_value()

        elif message.COMMAND == Commands.SMB2_CHANGE_NOTIFY:
            payload_size = message["output_buffer_length"].get_value()

        else:
            payload_size = 1

        credit_charge = (max(0, payload_size - 1) // MAX_PAYLOAD_SIZE) + 1
        return credit_charge


class Request:
    def __init__(self, message, message_type, connection, session_id=None):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.7 Per Pending Request
        For each request that was sent to the server and is await a response
        :param message: The message to be sent in the request
        :param message_type: The type of message that is set in the header's data field.
        :param connection: The Connection the request was sent under.
        :param session_id: The Session Id the request was for.
        """
        self.async_id = None
        self.message = message
        self.timestamp = datetime.now()
        self.cancelled = False

        # Used to contain the corresponding response from the server as the receiving in done in a separate thread.
        self.response = None

        # Used by the recv processing thread to say the response has been received and is ready for consumption.
        self.response_event = threading.Event()

        # Used to lock the request when the main thread is processing the PENDING result in case the background thread
        # receives the final result and fires the event before main clears it.
        self.response_event_lock = threading.Lock()

        # Stores the message_ids of related messages that are sent in a compound request. This is only set on the 1st
        # message in the request. Used when STATUS_STOPPED_ON_SYMLINK is set and we need to send the whole compound
        # request again with the new path.
        self.related_ids = []

        # Cannot rely on the message values as it could be a related compound msg which does not set these values.
        self.session_id = session_id

        # How the response was protected. Used to verify that a response that must be signed or encrypted actually was,
        # like a VALIDATE_NEGOTIATE_INFO response.
        self.response_encrypted = False
        self.response_signature_verified = False

        # Optional callback invoked by the message worker with the final response for requests sent internally, like
        # an oplock break acknowledgment, that no caller waits on.
        self.on_response = None

        self._connection = connection
        self._message_type = message_type  # Used to rehydrate the message data in case it's needed again.

    def cancel(self):
        if self.cancelled is True:
            return

        message_id = self.message["message_id"].get_value()
        log.info("Cancelling message %s", message_id)
        self._connection.send(
            SMB2CancelRequest(), sid=self.session_id, credit_request=0, message_id=message_id, async_id=self.async_id
        )
        self.cancelled = True

    def get_message_data(self):
        message_obj = self._message_type()
        message_obj.unpack(self.message["data"].get_value())
        return message_obj

    @property
    def response_protected(self):
        """Whether the response was either encrypted or had its signature verified."""
        return self.response_encrypted or self.response_signature_verified

    def update_request(self, new_request):
        self.async_id = new_request.async_id
        self.response_encrypted = new_request.response_encrypted
        self.response_signature_verified = new_request.response_signature_verified
        self.message = new_request.message
        self.timestamp = new_request.timestamp
        self.response = new_request.response
        self.response_event = new_request.response_event
        self.response_event_lock = new_request.response_event_lock
        self.related_ids = new_request.related_ids
