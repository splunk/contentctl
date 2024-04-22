from typing import Any

from pydantic import BaseModel


class NotableAction(BaseModel):
    """Representation of a notable action

    NOTE: this is NOT a representation of notable generated as a result of detection firing, but rather of the Adaptive
    Response Action that generates the notable
    :param rule_name: the name of the rule (detection/search) associated with the notable action (e.g. "ESCU -
        Windows Modify Registry EnableLinkedConnections - Rule")
    :param rule_description: a description of the rule (detection/search) associated with the notable action
    :param security_domain: the domain associated with the notable action and related rule (detection/search)
    :param severity: severity (e.g. "high") associated with the notable action and related rule (detection/search)
    """
    rule_name: str
    rule_description: str
    security_domain: str
    severity: str

    @classmethod
    def parse_from_dict(cls, dict_: dict[str, Any]) -> "NotableAction":
        """
        Given a dictionary of values, parses out specific keys to construct the instance

        :param dict_: a dictionary of with the expected keys
        :return: and instance of NotableAction
        :raises KeyError: if the dictionary given does not contain a required key
        """
        return cls(
            rule_name=dict_["action.notable.param.rule_title"],
            rule_description=dict_["action.notable.param.rule_description"],
            security_domain=dict_["action.notable.param.security_domain"],
            severity=dict_["action.notable.param.severity"]
        )
