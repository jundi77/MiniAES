from typing import Literal
from .operations.KeyOperation import KeyOperation
from .io.files.FileReaderInterface import FileReaderInterface
from .io.files.FileWriterInterface import FileWriterInterface
from .nonblock_mode.operations.NonBlockEncryptionOperation import NonBlockEncryptionOperation
from .nonblock_mode.data.NonBlockKey import NonBlockKey
from .nonblock_mode.data.NonBlockPlaintext import NonBlockPlaintext
from .nonblock_mode.data.NonBlockCiphertext import NonBlockCiphertext
from .block_mode.operations.BlockEncryptionOperation import BlockEncryptionOperation
from .block_mode.data.BlockKey import BlockKey
from .block_mode.data.BlockPlaintext import BlockPlaintext
from .block_mode.data.BlockCiphertext import BlockCiphertext
from .logs.LogManager import LogManager

class EncryptionFacade():
    @staticmethod
    def encrypt(plaintext: FileReaderInterface, key: FileReaderInterface, ciphertext: FileWriterInterface, block: Literal['nonblock', 'block']=None, block_mode: Literal['ecb', 'cbc']=None, logger: LogManager=None):
        if block == 'nonblock':
            e = NonBlockEncryptionOperation(
                NonBlockPlaintext(plaintext, 'enc'),
                KeyOperation(NonBlockKey(key)),
                NonBlockCiphertext(ciphertext, 'enc')
            )
            e.set_logger(logger)
            e.encrypt()
        elif block == 'block':
            if block_mode == 'ecb' or block_mode == 'cbc':
                e = BlockEncryptionOperation(
                    BlockPlaintext(plaintext, 'enc'),
                    KeyOperation(BlockKey(key)),
                    BlockCiphertext(ciphertext, 'enc'),
                    block_mode
                )
                e.set_logger(logger)
                e.encrypt()
            else:
                raise ValueError("invalid block mode.")
        else:
            raise ValueError("invalid operation type (block or nonblock).")
