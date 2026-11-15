"""HP Guided crash input pins are leads, never security verdicts."""

import hashlib

from vulnerabilityanalysis.assertions import _guided_crash_file_pins


def test_guided_crash_pins_bind_local_bytes_and_reject_external_paths(tmp_path):
    guided = tmp_path / "guided"
    guided.mkdir()
    crash = guided / "crash-one"
    crash.write_bytes(b"first input")
    outside = tmp_path / "crash-outside"
    outside.write_bytes(b"outside input")
    link = guided / "crash-link"
    link.symlink_to(outside)
    nested = guided / "linked-dir"
    nested.symlink_to(guided, target_is_directory=True)
    nested_crash = nested / "crash-one"

    pins = _guided_crash_file_pins(
        [str(crash), str(outside), str(link), str(nested_crash)], guided)
    assert pins == [
        {"path": str(crash),
         "sha256": hashlib.sha256(b"first input").hexdigest()},
        {"path": str(outside), "sha256": None},
        {"path": str(link), "sha256": None},
        {"path": str(nested_crash), "sha256": None},
    ]
    crash.write_bytes(b"changed input")
    assert _guided_crash_file_pins([str(crash)], guided)[0]["sha256"] != (
        pins[0]["sha256"])
