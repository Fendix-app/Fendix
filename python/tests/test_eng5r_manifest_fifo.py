"""Round 5 verification, redteam5-11: a named pipe called requirements.txt must
not hang the dependency analyzer. Opening it for reading waits for a writer."""

import os
import signal

import pytest

from analyzers.deps import _read_capped


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_a_named_pipe_manifest_is_refused_not_read(tmp_path):
    fifo = tmp_path / "requirements.txt"
    os.mkfifo(fifo)

    def timeout(*_):
        raise AssertionError("reading the manifest blocked on a named pipe")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(5)
    try:
        assert _read_capped(fifo) is None
    finally:
        signal.alarm(0)


def test_a_regular_manifest_is_still_read(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==2.0\n", encoding="utf-8")
    assert _read_capped(manifest) == "flask==2.0\n"
