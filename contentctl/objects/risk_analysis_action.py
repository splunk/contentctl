from typing import Any
import json

from pydantic import BaseModel

from contentctl.objects.risk_object import RiskObject
from contentctl.objects.threat_object import ThreatObject


class RiskAnalysisAction(BaseModel):
    """Representation of a risk analysis action

    NOTE: this is NOT a representation of risk event generated as a result of detection firing, but rather of the
    Adaptive Response Action that generates the risk event
    :param risk_objects: a list of RiskObject instances for this action
    :param message: the message associated w/ the risk event (NOTE: may contain macros of the form $...$ which
        should be replaced with real values in the resulting risk events)
    """
    risk_objects: list[RiskObject]
    message: str

    @classmethod
    def parse_from_dict(cls, dict_: dict[str, Any]) -> "RiskAnalysisAction":
        """
        Given a dictionary of values, parses out specific keys to construct one or more instances.

        The risk action has 1 or more associates risk objects (e.g. user, system, etc.). These are stored as a list of
        dicts inside the 'action.risk.param._risk' field, which we need to unpack the JSON of.
        :param dict_: a dictionary of with the expected keys
        :return: and instance of RiskAnalysisAction
        :raises KeyError: if the dictionary given does not contain a required key
        :raises json.JSONDecodeError: if the value at dict_['action.risk.param._risk'] can't be decoded from JSON into
            a dict
        :raises ValueError: if the value at dict_['action.risk.param._risk'] is unpacked to be anything
            other than a singleton or if an unexpected field is enoucountered within the singleton
        :return: a RiskAnalysisAction
        """
        object_dicts = json.loads(dict_["action.risk.param._risk"])

        if len(object_dicts) < 1:
            raise ValueError(
                f"Risk analysis action has no objects (threat nor risk) defined in 'action.risk.param._risk': "
                f"{dict_['action.risk.param._risk']}"
            )

        risk_objects: list[RiskObject] = []
        threat_objects: list[ThreatObject] = []

        # TODO: should we raise an error if we have only threat objects and no risk objects? Scoring is only a notion
        #   for risk objects as far as I'm aware
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