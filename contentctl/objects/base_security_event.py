from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict

from contentctl.objects.detection import Detection


class BaseSecurityEvent(BaseModel, ABC):
    """
    Base event class for a Splunk security event (e.g. risks and notables)
    """

    # The search name (e.g. "ESCU - Windows Modify Registry EnableLinkedConnections - Rule")
    search_name: str

    # The search ID that found that generated this event
    orig_sid: str

    # Allowing fields that aren't explicitly defined to be passed since some of the risk/notable
    # event's fields vary depending on the SPL which generated them
    model_config = ConfigDict(extra="allow")

    @abstractmethod
    def validate_against_detection(self, detection: Detection) -> None:
        """
        Validate this risk/notable event against the given detection
        """
        raise NotImplementedError()
