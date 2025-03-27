from contentctl.objects.base_security_event import BaseSecurityEvent
from contentctl.objects.detection import Detection


class NotableEvent(BaseSecurityEvent):
    # TODO (PEX-434): implement deeper notable validation
    # TODO (cmcginley): do I need to define the abstractmethods?
    pass

    def validate_against_detection(self, detection: Detection) -> None:
        """
        Validate this risk/notable event against the given detection
        """
        raise NotImplementedError()
