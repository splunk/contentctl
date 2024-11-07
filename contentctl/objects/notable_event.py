from pydantic import ConfigDict, BaseModel

from contentctl.objects.detection import Detection


# TODO (PEX-434): implement deeper notable validation
class NotableEvent(BaseModel):
    # The search name (e.g. "ESCU - Windows Modify Registry EnableLinkedConnections - Rule")
    search_name: str

    # The search ID that found that generated this risk event
    orig_sid: str

    # Allowing fields that aren't explicitly defined to be passed since some of the risk event's
    # fields vary depending on the SPL which generated them
    model_config = ConfigDict(
        extra='allow'
    )

    def validate_against_detection(self, detection: Detection) -> None:
        raise NotImplementedError()
