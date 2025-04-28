from abc import ABC, abstractmethod
from typing import Tuple

class Readable(ABC):
    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def read_data(self, close: bool = False) -> Tuple[int, int] | Tuple[None, int]:
        """
        Buffer is in 2 bytes.
        """
        pass
