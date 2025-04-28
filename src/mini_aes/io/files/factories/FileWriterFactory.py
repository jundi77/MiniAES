from typing import Literal
from io import BytesIO
from ..implementations.BinaryFileWriter import BinaryFileWriter
from ..FileWriterInterface import FileWriterInterface

class FileWriterFactory():
    @staticmethod
    def create(config: Literal['binary'], filepath: str=None, file_io: BytesIO=None) -> FileWriterInterface:
        if config == 'binary':
            return BinaryFileWriter(filepath, file_io)
        else:
            raise ValueError(f"Invalid config for file writer: {config}")
