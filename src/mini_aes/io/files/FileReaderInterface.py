from abc import ABC, abstractmethod
from typing import Iterator, Tuple

class FileReaderInterface(ABC):
    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def read(self, buffer_bytes: int, close: bool) -> Iterator[bytes] | Iterator[str] | None:
        pass
