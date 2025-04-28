from typing import Callable, List

class LogManager():
    def __init__(self):
        self.__events: List[str] = []
        self.__subscriber: List[Callable] = []

    def subscribe(self, receiver: Callable):
        self.__subscriber.append(receiver)

    def push(self, event: str):
        self.__events.append(event)
        for s in self.__subscriber:
            s(event)

    def export(self, filename: str):
        with open(filename, 'w') as f:
            f.writelines(self.__events)
