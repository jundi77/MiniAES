from typing import Literal
from io import BytesIO
from ..implementations.BinaryFileReader import BinaryFileReader
from ..FileReaderInterface import FileReaderInterface

class FileReaderFactory():
    @staticmethod
    def create(config: Literal['binary'], filepath: str=None, file_io: BytesIO=None) -> FileReaderInterface:
        if config == 'binary':
            return BinaryFileReader(filepath, file_io)
        else:
            raise ValueError(f"Invalid config for file reader: {config}")
