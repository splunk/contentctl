from contentctl.objects.base_security_event import BaseSecurityEvent
from contentctl.objects.detection import Detection


class NotableEvent(BaseSecurityEvent):
    # TODO (PEX-434): implement deeper notable validation

    def validate_against_detection(self, detection: Detection) -> None:
        """
        Validate this risk/notable event against the given detection
        """
        raise NotImplementedError()
