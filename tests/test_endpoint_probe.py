"""The original-server port probe must distinguish live listeners from TCP TIME_WAIT."""

from __future__ import annotations

import socket
import unittest

from harnesscreator.runtime.scenario import _assert_endpoint_available


class EndpointProbeTests(unittest.TestCase):
    def test_active_tcp_listener_is_rejected(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with self.assertRaisesRegex(OSError, "already occupied"):
                _assert_endpoint_available(
                    "127.0.0.1", listener.getsockname()[1], "tcp"
                )

    def test_time_wait_from_previous_trial_is_not_a_live_listener(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.listen(1)
            with socket.create_connection(("127.0.0.1", port)) as client:
                accepted, _ = listener.accept()
                accepted.close()  # The server side enters TIME_WAIT.
                client.settimeout(1.0)
                self.assertEqual(client.recv(1), b"")

        with socket.socket() as plain_probe:
            try:
                plain_probe.bind(("127.0.0.1", port))
            except OSError:
                pass
            else:
                self.skipTest("platform did not retain the closed TCP address")

        _assert_endpoint_available("127.0.0.1", port, "tcp")
