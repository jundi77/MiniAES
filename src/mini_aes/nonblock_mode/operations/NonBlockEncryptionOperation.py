from ..data.NonBlockPlaintext import NonBlockPlaintext
from ..data.NonBlockCiphertext import NonBlockCiphertext
from ...operations.KeyOperation import KeyOperation
from ...operations.EncryptionOperationBase import EncryptionOperationBase

class NonBlockEncryptionOperation(EncryptionOperationBase):
    def __init__(self, plaintext: NonBlockPlaintext, key: KeyOperation, ciphertext: NonBlockCiphertext):
        super().__init__(plaintext, key, ciphertext)

    def encrypt(self) -> None:
        """
        strict 16 bit i/o.
        """
        data, length = self._plaintext.read_data(True)
        if data is None:
            raise ValueError("Plaintext is empty.")

        if length < 2 or (not self._plaintext.ended()):
            data, length = self._plaintext.read_data(True)
            raise ValueError("Plaintext has to be 2 bytes.")

        self._ciphertext.write_data(
            self._do_rounds(data),
            True
        )
