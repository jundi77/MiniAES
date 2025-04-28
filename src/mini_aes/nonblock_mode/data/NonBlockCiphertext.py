from typing import Literal, Tuple
from ...utils.Bit import Bit
from ...data.CiphertextBase import CiphertextBase
from ...io.files.FileReaderInterface import FileReaderInterface
from ...io.files.FileWriterInterface import FileWriterInterface

class NonBlockCiphertext(CiphertextBase):
    def __init__(self, file_io: FileReaderInterface | FileWriterInterface, mode: Literal["enc", "dec"]):
        super().__init__(file_io, mode)
        self._ended = False

    def ended(self) -> bool:
        return self._ended

    def read_data(self, close: bool = False) -> Tuple[int, int] | Tuple[None, int]:
        super().read_data(2)

        if self.ended():
            return None, 0

        data, stop = self._file_io.read()
        if stop:
            self._ended = True

        if isinstance(data, str):
            data: bytes = data.encode()

        if len(data) > 2:
            raise ValueError("Ciphertext in NonBlock operation only allow 4 nibbles (2 bytes) of data.")

        if data is None or data == b'':
            return None, 0
        else:
            return int.from_bytes(data, 'little'), len(data)

    def write_data(self, data: bytes | str | int, length: int = 2, close: bool = False) -> None:
        super().write_data(data)
        if (isinstance(data, bytes) and len(data) > 2) or (isinstance(data, str) and len(data.encode()) > 2) or Bit.check_2bytes(data):
            raise ValueError("Ciphertext writing operation only allow 4 nibbles (2 bytes) of data at a time.")

        if isinstance(data, int):
            data = data.to_bytes(2, 'little')

        self._file_io.write(data, True)
