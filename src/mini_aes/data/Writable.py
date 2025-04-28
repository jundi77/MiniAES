from abc import ABC, abstractmethod

class Writable(ABC):
    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def write_data(self, data: bytes | str | int, close: bool = False) -> None:
        """
        length is in byte.
        """
        pass
