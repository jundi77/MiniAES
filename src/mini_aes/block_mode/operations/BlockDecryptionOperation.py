from typing import Literal
from .BlockOperation import BlockOperation
from ..data.BlockPlaintext import BlockPlaintext
from ..data.BlockCiphertext import BlockCiphertext
from ...utils.Bit import Bit
from ...operations.KeyOperation import KeyOperation
from ...operations.DecryptionOperationBase import DecryptionOperationBase

class BlockDecryptionOperation(DecryptionOperationBase, BlockOperation):
    def __init__(self, ciphertext: BlockCiphertext, key: KeyOperation, plaintext: BlockPlaintext, mode: Literal["ecb", "cbc"]):
        BlockOperation.__init__(self, mode)
        DecryptionOperationBase.__init__(self, ciphertext, key, plaintext)

    def _decrypt_ecb(self) -> None:
        data, _ = self._ciphertext.read_data()
        if data is None:
            raise ValueError("Ciphertext is empty.")

        while (data is not None):
            self.log(f"Decryption will start for piece: {hex(data)}")

            p = self._do_inv_rounds(data)
            # print(("plaintext gross", hex(p)))
            # TODO bug hunt
            try:
                text = p.to_bytes((p.bit_length() + 7) // 8, 'little').decode()
                self.log(f"Decrypted to: {text}")
            except:
                self.log(f"Decrypted to: {hex(p)}")
            # self.log(f"Decrypted to: {hex(p)}")

            if self._ciphertext.ended():
                # print(("ended, check padding", hex(data)))
                p = Bit.remove_pad(p, 2)
                self.log(f"remove pad if padded: {None if p is None else hex(p)}")

            if p is not None:
                # case if last 2 bytes are padding
                self._plaintext.write_data(p)

            data, _ = self._ciphertext.read_data()

        self._ciphertext.close()
        self._plaintext.close()

    def _decrypt_cbc(self) -> None:
        iv, _ = self._ciphertext.read_data()
        # print(("iv gross", hex(iv)))
        if iv is None:
            raise ValueError("Ciphertext is empty.")

        data, _ = self._ciphertext.read_data()
        # print(("ciphertext gross", hex(data)))
        if data is None:
            raise ValueError("Ciphertext file does not have ciphertext (is it corrupt?).")

        self.log(f"Decryption will start for piece: {hex(data)}")
        self.log(f"IV is: {hex(iv)}")

        prev = iv
        while (data is not None):
            self.log(f"Decryption will start for piece: {hex(data)}")
            p = self._do_inv_rounds(data)
            # print(("plaintext gross", hex(p)))

            p ^= prev
            self.log(f"piece xored with prev block/iv: {hex(p)}, prev block/iv: {hex(prev)}")

            # print(("plaintext xor'ed", hex(p)))

            if self._ciphertext.ended():
                # case if last 2 bytes are padding
                p = Bit.remove_pad(p, 2)
                self.log(f"remove pad if padded: {None if p is None else hex(p)}")
                # print(("plaintext remove pad", None if data is None else hex(data)))

            # print(("plaintext", None if data is None else hex(data)))
            if p is not None:
                self._plaintext.write_data(p)

            prev = data
            data, _ = self._ciphertext.read_data()
            # if data is not None:
            #     data ^= p
            # print(("ciphertext gross", None if data is None else hex(data)))

        self._ciphertext.close()
        self._plaintext.close()

    def decrypt(self) -> None:
        if self._mode == "ecb":
            self._decrypt_ecb()
        elif self._mode == "cbc":
            self._decrypt_cbc()
