import asyncio
import unittest
from harnesscreator.runtime.memcached_frames import FrameError, read_response

class MemcachedFramesTest(unittest.IsolatedAsyncioTestCase):
    async def observe(self, request, chunks):
        reader = asyncio.StreamReader()
        async def produce():
            for chunk in chunks:
                reader.feed_data(chunk)
                await asyncio.sleep(0)
            reader.feed_eof()
        producer = asyncio.create_task(produce())
        try:
            return await read_response(reader, request, limit=1024, timeout=2)
        finally:
            await producer

    async def test_not_stored_is_failure_even_when_fragmented(self):
        data, success = await self.observe(b'add k 0 0 1\r\nx\r\n', [b'NOT_', b'STORED\r', b'\n'])
        self.assertEqual(data, b'NOT_STORED\r\n')
        self.assertFalse(success)

    async def test_get_waits_for_body_and_end(self):
        response = b'VALUE k 0 4\r\na\r\nb\r\nEND\r\n'
        data, success = await self.observe(b'get k\r\n', [response[:12], response[12:18], response[18:]])
        self.assertEqual(data, response)
        self.assertTrue(success)

    async def test_get_miss_and_wrong_key(self):
        _, success = await self.observe(b'get k\r\n', [b'END\r\n'])
        self.assertFalse(success)
        with self.assertRaises(FrameError):
            await self.observe(b'get k\r\n', [b'VALUE other 0 1\r\nx\r\nEND\r\n'])

    async def test_incomplete_response_is_not_success(self):
        with self.assertRaises(FrameError):
            await self.observe(b'get k\r\n', [b'VALUE k 0 1\r\nx\r\n'])

    async def test_concatenated_requests_are_not_accepted(self):
        with self.assertRaises(FrameError):
            await self.observe(b'get k\r\nget other\r\n', [b'END\r\n'])
        with self.assertRaises(FrameError):
            await self.observe(b'set k 0 0 1\r\nx\r\nget k\r\n', [b'STORED\r\n'])

if __name__ == '__main__':
    unittest.main()

