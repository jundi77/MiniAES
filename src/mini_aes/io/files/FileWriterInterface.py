from abc import ABC, abstractmethod

class FileWriterInterface(ABC):
    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def write(self, data: bytes | str, close: bool) -> None:
        pass
