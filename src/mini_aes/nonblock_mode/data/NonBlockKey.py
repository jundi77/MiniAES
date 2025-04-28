from typing import Tuple
from ...data.KeyBase import KeyBase
from ...io.files.FileReaderInterface import FileReaderInterface

class NonBlockKey(KeyBase):
    """
    Per requirements, only do i/o in 4 nibbles (2 bytes).
    """

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

        if len(data) > 2:
            raise ValueError("Key in NonBlock operation only allow 4 nibbles (2 bytes) of data.")

        if data is None or data == b'':
            return None, 0
        else:
            return int.from_bytes(data, 'little'), len(data)
