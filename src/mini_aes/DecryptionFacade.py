from typing import Literal
from .operations.KeyOperation import KeyOperation
from .io.files.FileReaderInterface import FileReaderInterface
from .io.files.FileWriterInterface import FileWriterInterface
from .nonblock_mode.operations.NonBlockDecryptionOperation import NonBlockDecryptionOperation
from .nonblock_mode.data.NonBlockKey import NonBlockKey
from .nonblock_mode.data.NonBlockPlaintext import NonBlockPlaintext
from .nonblock_mode.data.NonBlockCiphertext import NonBlockCiphertext
from .block_mode.operations.BlockDecryptionOperation import BlockDecryptionOperation
from .block_mode.data.BlockKey import BlockKey
from .block_mode.data.BlockPlaintext import BlockPlaintext
from .block_mode.data.BlockCiphertext import BlockCiphertext
from .logs.LogManager import LogManager

class DecryptionFacade():
    @staticmethod
    def decrypt(ciphertext: FileReaderInterface, key: FileReaderInterface, plaintext: FileWriterInterface, block: Literal['nonblock', 'block']=None, block_mode: Literal['ecb', 'cbc']=None, logger: LogManager=None):
        if block == 'nonblock':
            e = NonBlockDecryptionOperation(
                NonBlockCiphertext(ciphertext, 'dec'),
                KeyOperation(NonBlockKey(key)),
                NonBlockPlaintext(plaintext, 'dec'),
            )
            e.set_logger(logger)
            e.decrypt()
        elif block == 'block':
            if block_mode == 'ecb' or block_mode == 'cbc':
                e = BlockDecryptionOperation(
                    BlockCiphertext(ciphertext, 'dec'),
                    KeyOperation(BlockKey(key)),
                    BlockPlaintext(plaintext, 'dec'),
                    block_mode
                )
                e.set_logger(logger)
                e.decrypt()
            else:
                raise ValueError("invalid block mode.")
        else:
            raise ValueError("invalid operation type (block or nonblock).")
