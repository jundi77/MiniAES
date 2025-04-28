from abc import ABC
from typing import Final, Literal

class BlockOperation(ABC):
    VALID_MODE: Final[list["str"]] = ["ecb", "cbc"]

    def __init__(self, mode: Literal["ecb", "cbc"]):
        super().__init__()
        if mode not in BlockOperation.VALID_MODE:
            raise ValueError(f"Invalid mode ({mode}), expecting one of {self.VALID_MODE}")

        self._mode = mode
