from typing import Tuple
from ...data.KeyBase import KeyBase
from ...io.files.FileReaderInterface import FileReaderInterface

class BlockKey(KeyBase):
    def __init__(self, file_io: FileReaderInterface):
        super().__init__(file_io)
        self._ended = False

    def ended(self) -> bool:
        return self._ended

    def read_data(self) -> Tuple[int, int] | Tuple[None, int]:
        super().read_data(2)

        if self.ended():
            return None, 0

        data, stop = self._file_io.read()
        if stop:
            self._ended = True

        if isinstance(data, str):
            data: bytes = data.encode()

        return int.from_bytes(data, 'little'), len(data)
