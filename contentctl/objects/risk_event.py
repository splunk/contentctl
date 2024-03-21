from pydantic import BaseModel, Extra


class RiskEvent(BaseModel):
    # The search name (e.g. "ESCU - Windows Modify Registry EnableLinkedConnections - Rule")
    search_name: str

    # The subject of the risk event (e.g. a username, process name, or system name)
    risk_object: str

    # The type of the risk object (e.g. user, system, or other)
    risk_object_type: str

    # The level of risk associated w/ the risk event
    risk_score: int

    # The search ID that found that generated this risk event
    orig_sid: str

    # The message for the risk event
    risk_message: str

    # The description of the detection / correlation search
    savedsearch_description: str

    class Config:
        # Allowing fields that aren't explicitly defined to be passed since some of the risk event's
        # fields vary depending on the SPL which generated them
        extra = Extra.allow
