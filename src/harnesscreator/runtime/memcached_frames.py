"""Bounded parser for a deliberately limited memcached ASCII response subset."""
import asyncio

class FrameError(ValueError):
    pass

async def read_response(reader: asyncio.StreamReader, request: bytes, *, limit: int, timeout: float) -> tuple[bytes, bool]:
    """Read one full supported response; unknown or malformed forms fail closed."""
    async def run():
        data = bytearray()
        async def line():
            try:
                item = await reader.readuntil(b'\r\n')
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
                raise FrameError('incomplete or oversized line') from exc
            if len(data) + len(item) > limit:
                raise FrameError('response exceeds limit')
            data.extend(item)
            return item

        raw_header, separator, request_body = request.partition(b'\r\n')
        if not separator:
            raise FrameError('incomplete request header')
        request_line = raw_header.split()
        if not request_line:
            raise FrameError('empty request')
        command = request_line[0].lower()
        if command in {b'set', b'add', b'replace', b'append', b'prepend', b'cas'}:
            if len(request_line) != (6 if command == b'cas' else 5):
                raise FrameError('unsupported storage request')
            if any(not part.isdigit() for part in request_line[2:]):
                raise FrameError('invalid storage metadata')
            size = int(request_line[4])
            if len(request_body) != size + 2 or not request_body.endswith(b'\r\n'):
                raise FrameError('incomplete or concatenated storage request')
            result = await line()
            if result == b'STORED\r\n':
                return bytes(data), True
            if result in {b'NOT_STORED\r\n', b'EXISTS\r\n', b'NOT_FOUND\r\n', b'ERROR\r\n'} or result.startswith((b'CLIENT_ERROR ', b'SERVER_ERROR ')):
                return bytes(data), False
            raise FrameError('unknown storage response')
        if command not in {b'get', b'gets'} or len(request_line) != 2 or request_body:
            raise FrameError('unsupported request')
        keys = set(request_line[1:])
        seen = set()
        while True:
            header = await line()
            if header == b'END\r\n':
                return bytes(data), bool(seen)
            if header == b'ERROR\r\n' or header.startswith((b'CLIENT_ERROR ', b'SERVER_ERROR ')):
                return bytes(data), False
            parts = header[:-2].split()
            if len(parts) != (5 if command == b'gets' else 4) or parts[0] != b'VALUE' or parts[1] not in keys or parts[1] in seen:
                raise FrameError('invalid VALUE header')
            if not parts[2].isdigit() or not parts[3].isdigit() or (command == b'gets' and not parts[4].isdigit()):
                raise FrameError('invalid VALUE metadata')
            size = int(parts[3])
            if size + 2 > limit - len(data):
                raise FrameError('value exceeds response limit')
            try:
                value = await reader.readexactly(size + 2)
            except asyncio.IncompleteReadError as exc:
                raise FrameError('incomplete VALUE body') from exc
            data.extend(value)
            if not value.endswith(b'\r\n'):
                raise FrameError('invalid VALUE terminator')
            seen.add(parts[1])
    return await asyncio.wait_for(run(), timeout)
