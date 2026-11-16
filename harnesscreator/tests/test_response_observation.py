"""Response bytes without framing evidence remain observations, not verdicts."""

import asyncio
import os
import unittest

from harnesscreator.runtime.scenario import (
    ResponseReadTimeout, _read_fd_until_oracle, _read_until_oracle,
)


class DescriptorResponseObservationTests(unittest.TestCase):
    def test_partial_fd_reply_survives_timeout(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"PO")
            with self.assertRaises(ResponseReadTimeout) as caught:
                _read_fd_until_oracle(read_fd, [b"PONG\n"], 1024, 0.02, 0)
            self.assertEqual(caught.exception.partial, b"PO")
        finally:
            os.close(read_fd)
            os.close(write_fd)


class ResponseObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_unframed_reply_returns_available_bytes_without_waiting_for_eof(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"SSH-2.0-server\r\n")
        response = await asyncio.wait_for(
            _read_until_oracle(reader, [], limit=1024, timeout=1.0),
            timeout=0.1,
        )
        self.assertEqual(response, b"SSH-2.0-server\r\n")
        self.assertFalse(reader.at_eof())

    async def test_partial_framed_reply_survives_timeout(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"PO")
        with self.assertRaises(ResponseReadTimeout) as caught:
            await _read_until_oracle(reader, [b"PONG\n"], limit=1024, timeout=0.02)
        self.assertEqual(caught.exception.partial, b"PO")

    async def test_framed_reply_waits_for_marker(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"PO")

        async def finish() -> None:
            await asyncio.sleep(0.01)
            reader.feed_data(b"NG\n")

        writer = asyncio.create_task(finish())
        try:
            response = await _read_until_oracle(
                reader, [b"PONG\n"], limit=1024, timeout=0.5,
            )
        finally:
            await writer
        self.assertEqual(response, b"PONG\n")
