# Copyright: (c) 2026, Acconeer AB <henrik.nilsson@acconeer.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import warnings

import pytest

import smbclient._io as io
from smbclient._io import SMBRawIO


@pytest.fixture
def raw(mocker):
    """Construct an SMBRawIO without opening any socket.

    SMBRawIO.__init__ normally calls get_smb_tree which establishes a connection.
    Patching that and Open lets the finalizer be exercised deterministically.
    """
    mock_tree = mocker.MagicMock()
    mocker.patch.object(io, "get_smb_tree", return_value=(mock_tree, "file"))
    mocker.patch.object(io, "Open")

    return SMBRawIO(r"\\server\share\file.txt", mode="r", share_access="r")


def test_del_does_not_close_a_connected_handle(raw):
    # The override must skip self.close() to avoid deadlocking the worker.
    raw.fd.connected = True

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        raw.__del__()

    raw.fd.close.assert_not_called()


def test_del_emits_resource_warning_for_leaked_handle(raw):
    raw.fd.connected = True

    with pytest.warns(ResourceWarning, match=r"unclosed SMB handle"):
        raw.__del__()


def _raw_with_reads(mocker, raw_type, end_of_file, chunks):
    raw = raw_type.__new__(raw_type)
    raw.fd = mocker.MagicMock()
    raw.fd.connected = False
    raw.fd.end_of_file = end_of_file
    raw.fd.connection.max_read_size = 65536
    raw._offset = 0
    reads = list(chunks)

    def readinto(b):
        data = reads.pop(0) if reads else b""
        b[: len(data)] = data
        raw._offset += len(data)
        return len(data)

    raw.readinto = readinto
    return raw


def test_readall_file(mocker):
    raw = _raw_with_reads(mocker, io.SMBFileIO, 8, [b"abc", b"defgh"])
    assert raw.readall() == b"abcdefgh"


def test_readall_file_shrunk(mocker):
    # The server returned less data than the cached end of file.
    raw = _raw_with_reads(mocker, io.SMBFileIO, 10, [b"abcd", b"efg"])
    assert raw.readall() == b"abcdefg"


def test_readall_file_at_end(mocker):
    raw = _raw_with_reads(mocker, io.SMBFileIO, 4, [b"abcd"])
    raw._offset = 4
    assert raw.readall() == b""


def test_readall_pipe(mocker):
    # A pipe has no end of file, it is read until no more data is returned.
    raw = _raw_with_reads(mocker, io.SMBPipeIO, 0, [b"abc", b"def"])
    assert raw.readall() == b"abcdef"
