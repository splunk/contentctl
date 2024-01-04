from typing import Any
import json

from pydantic import BaseModel, validator

from contentctl.objects.risk_object import RiskObject
from contentctl.objects.threat_object import ThreatObject


# TODO (cmcginley): add logic which reports concretely that integration testing failed (or would fail)
#   as a result of a missing victim observable
class RiskAnalysisAction(BaseModel):
    """Representation of a risk analysis action

    NOTE: this is NOT a representation of risk event generated as a result of detection firing, but
    rather of the Adaptive Response Action that generates the risk event
    :param risk_objects: a list of RiskObject instances for this action
    :param message: the message associated w/ the risk event (NOTE: may contain macros of the form
        $...$ which should be replaced with real values in the resulting risk events)
    """
    risk_objects: list[RiskObject]
    message: str

    @validator("message", always=True, pre=True)
    @classmethod
    def _validate_message(cls, v, values) -> str:
        """
        Validate splunk_path and derive if None
        """
        if v is None:
            raise ValueError(
                "RiskAnalysisAction.message is a required field, cannot be None. Check the "
                "detection YAML definition to ensure a message is defined"
            )

        if not isinstance(v, str):
            raise ValueError(
                "RiskAnalysisAction.message must be a string. Check the detection YAML definition "
                "to ensure message is defined as a string"
            )

        if len(v.strip()) < 1:
            raise ValueError(
                "RiskAnalysisAction.message must be a meaningful string, with a length greater than"
                "or equal to 1 (once stripped of trailing/leading whitespace). Check the detection "
                "YAML definition to ensure message is defined as a meanigful string"
            )

        return v

    @classmethod
    def parse_from_dict(cls, dict_: dict[str, Any]) -> "RiskAnalysisAction":
        """
        Given a dictionary of values, parses out specific keys to construct one or more instances.

        The risk action has 1 or more associated risk objects (e.g. user, system, etc.). These are
        stored as a list of dicts inside the 'action.risk.param._risk' field, which we need to
        unpack the JSON of.
        :param dict_: a dictionary of with the expected keys
        :return: and instance of RiskAnalysisAction
        :raises KeyError: if the dictionary given does not contain a required key
        :raises json.JSONDecodeError: if the value at dict_['action.risk.param._risk'] can't be
            decoded from JSON into a dict
        :raises ValueError: if the value at dict_['action.risk.param._risk'] is unpacked to be
            anything other than a singleton or if an unexpected field is enoucountered within the
            singleton
        :return: a RiskAnalysisAction
        """
        object_dicts = json.loads(dict_["action.risk.param._risk"])

        if len(object_dicts) < 1:
            raise ValueError(
                f"Risk analysis action has no objects (threat nor risk) defined in "
                f"'action.risk.param._risk': {dict_['action.risk.param._risk']}"
            )

        risk_objects: list[RiskObject] = []
        threat_objects: list[ThreatObject] = []

        # TODO (cmcginley): add validation ensuring at least 1 risk objects
        for entry in object_dicts:
            if "risk_object_field" in entry:
                risk_objects.append(RiskObject(
                    field=entry["risk_object_field"],
                    type=entry["risk_object_type"],
                    score=int(entry["risk_score"])
                ))
            elif "threat_object_field" in entry:
                threat_objects.append(ThreatObject(
                    field=entry["threat_object_field"],
                    type=entry["threat_object_type"]
                ))
            else:
                raise ValueError(
                    f"Unexpected object within 'action.risk.param._risk': {entry}"
                )
        return cls(
            risk_objects=risk_objects,
            message=dict_["action.risk.param._risk_message"]
        )
