from ..data.NonBlockPlaintext import NonBlockPlaintext
from ..data.NonBlockCiphertext import NonBlockCiphertext
from ...operations.KeyOperation import KeyOperation
from ...operations.DecryptionOperationBase import DecryptionOperationBase

class NonBlockDecryptionOperation(DecryptionOperationBase):
    def __init__(self, ciphertext: NonBlockCiphertext, key: KeyOperation, plaintext: NonBlockPlaintext):
        super().__init__(ciphertext, key, plaintext)

    def decrypt(self) -> None:
        """
        strict 16 bit i/o.
        """
        data, length = self._ciphertext.read_data(True)
        if data is None:
            raise ValueError("Ciphertext is empty.")

        if length < 2 or (not self._ciphertext.ended()):
            raise ValueError("Ciphertext has to be 2 bytes.")

        self._plaintext.write_data(
            self._do_inv_rounds(data),
            True
        )
