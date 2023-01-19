from pydantic import BaseModel
import abc


class DetectionTestingViewController(BaseModel, abc.ABC):
    interval: float = 10
    next_update: float = 0

    def setup(self):
        pass

    def showStatus(self, elapsed_seconds: float):
        pass

    def showResults(self):
        pass

    def createReport(self):
        pass
