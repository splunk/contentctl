import re
from typing import Union, Optional

from pydantic import BaseModel, Extra, Field, PrivateAttr, validator

from contentctl.objects.errors import ValidationFailed
from contentctl.objects.detection import Detection
from contentctl.objects.observable import Observable

# TODO: use SES_OBSERVABLE_TYPE_MAPPING
TYPE_MAP: dict[str, list[str]] = {
    "user": ["User"],
    "system": ["Hostname", "IP Address", "Endpoint"],
    "other": ["Process", "URL String", "Unknown", "Process Name"],
}
# TODO: 'Email Address', 'File Name', 'File Hash', 'Other', 'User Name', 'File', 'Process Name'

# TODO: use SES_OBSERVABLE_ROLE_MAPPING
IGNORE_ROLES: list[str] = ["Attacker"]
# Known valid roles: Victim, Parent Process, Child Process
# TODO: 'Other', 'Target', 'Unknown'
# TODO: is Other a valid role

# TODO: do we need User Name in conjunction w/ User? User Name doesn't get mapped to "user" in risk events
# TODO: similarly, do we need Process and Process Name?

RESERVED_FIELDS = ["host"]


class RiskEvent(BaseModel):
    """Model for risk event in ES"""

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

    # The analytic stories applicable to this risk event
    analyticstories: Optional[list[str]] = Field(default=None)

    # The MITRE ATT&CK IDs
    annotations_mitre_attack: Optional[list[str]] = Field(
        alias="annotations.mitre_attack",
        default=None
    )

    # Private attribute caching the observable this RiskEvent is mapped to
    _matched_observable: Observable = PrivateAttr(default=None)

    class Config:
        # Allowing fields that aren't explicitly defined to be passed since some of the risk event's
        # fields vary depending on the SPL which generated them
        extra = Extra.allow

    @validator("annotations_mitre_attack", "analyticstories", pre=True, always=True)
    @classmethod
    def _convert_str_value_to_singleton(cls, v, values) -> str:
        """
        Given a value, determine if its a list or a single str value; if a single value, return as a
        singleton. Do nothing if anything else.
        """
        if isinstance(v, list):
            return v
        elif isinstance(v, str):
            return [v]

        return v

    def validate_against_detection(self, detection: Detection) -> None:
        """
        Given the associated detection, validate the risk event against its fields
        :param detection: the detection associated w/ this risk event
        :raises: ValidationFailed
        """
        # Check risk_score
        if self.risk_score != detection.tags.risk_score:
            raise ValidationFailed(
                f"Risk score observed in risk event ({self.risk_score}) does not match risk score in "
                f"detection ({detection.tags.risk_score})."
            )

        # Check analyticstories
        self.validate_analyticstories(detection)

        # Check annotations.mitre_attack
        self.validate_mitre_ids(detection)

        # Check search_name
        if self.search_name != f"ESCU - {detection.name} - Rule":
            raise ValidationFailed(
                f"Saved Search name in risk event ({self.search_name}) does not match detection name "
                f"({detection.name})."
            )

        # Check risk_message
        self.validate_risk_message(detection)

        # TODO: Re-enable this check once we have refined the logic and reduced the false positive
        #   rate in risk/obseravble matching
        # Check several conditions against the observables
        # self.validate_risk_against_observables(detection.tags.observable)

    def validate_mitre_ids(self, detection: Detection) -> None:
        """
        Given the associated detection, validate the risk event's MITRE attack IDs
        """
        # Convert to lists if needed so we can use the equality below
        risk_mitre = self.annotations_mitre_attack
        detection_mitre = detection.tags.mitre_attack_id
        if risk_mitre is None:
            risk_mitre = [risk_mitre]
        if detection_mitre is None:
            detection_mitre = [detection_mitre]

        # Check annotations.mitre_attack
        if sorted(risk_mitre) != sorted(detection_mitre):
            raise ValidationFailed(
                f"MITRE ATT&CK IDs in risk event ({self.annotations_mitre_attack}) do not match those"
                f" in detection ({detection.tags.mitre_attack_id})."
            )

    def validate_analyticstories(self, detection: Detection) -> None:
        """
        Given the associated detection, validate the risk event's MITRE analytic stories
        """
        # Convert to lists if needed so we can use the equality below
        risk_analytic = self.analyticstories
        detection_analytic = detection.tags.analytic_story
        if risk_analytic is None:
            risk_analytic = [risk_analytic]
        if detection_analytic is None:
            detection_analytic = [detection_analytic]

        # Check analyticstories
        if sorted(risk_analytic) != sorted(detection_analytic):
            raise ValidationFailed(
                f"Analytic stories in risk event ({self.analyticstories}) do not match those"
                f" in detection ({detection.tags.analytic_story})."
            )

    def validate_risk_message(self, detection: Detection) -> None:
        # Check for string literals of the form "$...$" in the observed risk message
        field_replacement_pattern = re.compile(r"\$\S+\$")
        if field_replacement_pattern.search(self.risk_message) is not None:
            raise ValidationFailed(
                f"Unreplaced field replacement string found in risk message: {self.risk_message}"
            )

        # Convert detection source message to regex pattern; we need to first sub in a placeholder
        # so we can escape the string, and then swap in the actual regex elements in place of the
        # placeholder
        tmp_placeholder = "PLACEHOLDERPATTERNFORESCAPING"
        escaped_source_message_with_placeholder = re.escape(
            field_replacement_pattern.sub(
                tmp_placeholder,
                detection.tags.message
            )
        )
        placeholder_replacement_pattern = re.compile(tmp_placeholder)
        final_risk_message_pattern = re.compile(
            placeholder_replacement_pattern.sub(".+", escaped_source_message_with_placeholder)
        )

        # Check created regex pattern againt the observed risk message
        if final_risk_message_pattern.match(self.risk_message) is None:
            raise ValidationFailed(
                "Risk message in event does not match the pattern set by the detection. Message in "
                f"risk event: \"{self.risk_message}\". Message in detection: "
                f"\"{detection.tags.message}\"."
            )

    def validate_risk_against_observables(self, observables: list[Observable]) -> None:
        # Get the matched observable; will raise validation errors if no match can be made or if
        # risk is missing values associated w/ observables
        matched_observable = self.get_matched_observable(observables)

        # The risk object type should match our mapping of observable types to risk types
        expected_type = RiskEvent.observable_type_to_risk_type(matched_observable.type)
        if self.risk_object_type != expected_type:
            raise ValidationFailed(
                f"The risk object type ({self.risk_object_type}) does not match the expected type "
                f"based on the matched observable ({matched_observable.type}=={expected_type})."
            )

    @staticmethod
    def observable_type_to_risk_type(observable_type: str):
        for risk_type in TYPE_MAP:
            if observable_type in TYPE_MAP[risk_type]:
                return risk_type

        raise ValueError(
            f"Observable type {observable_type} does not have a mapping to a risk type in TYPE_MAP"
        )

    # TODO: should this be an observable instance method? It feels less relevant to observables
    #   themselves, as it's really only relevant to the handling of risk events
    @staticmethod
    def ignore_observable(observable: Observable) -> bool:
        ignore = False
        for role in observable.role:
            if role in IGNORE_ROLES:
                ignore = True
                break
        return ignore

    # TODO: two possibilities: alway check for the field itself and the field prefixed w/ "orig_"
    #   OR more explicitly maintain a list of known "reserved fields", like "host". I think I like
    #   option 2 better as it can have fewer unknown side effects
    def matches_observable(self, observable: Observable) -> bool:
        # When field names collide w/ reserved fields in Splunk events (e.g. sourcetype or host)
        # they get prefixed w/ "orig_"
        attribute_name = observable.name
        if attribute_name in RESERVED_FIELDS:
            attribute_name = f"orig_{attribute_name}"

        # Retrieve the value of this attribute and see if it matches the risk_object
        value: Union[str, list[str]] = getattr(self, attribute_name)
        if isinstance(value, str):
            value = [value]

        # The value of the attribute may be a list of values, so check for any matches
        return self.risk_object in value

    def get_matched_observable(self, observables: list[Observable]) -> Observable:
        if self._matched_observable is not None:
            return self._matched_observable

        matched_observable: Optional[Observable] = None

        for observable in observables:
            # Each the field name used in each observable shoud be present in the risk event
            # TODO: this check is redundant I think; earlier in the unit test, observable field
            #   names are compared against the search result set, ensuring all are present; if all
            #   are present in the result set, all are present in the risk event
            if not hasattr(self, observable.name):
                raise ValidationFailed(
                    f"Observable field \"{observable.name}\" not found in risk event."
                )

            # Try to match the risk_object against a specific observable for the obervables with
            # a valid role (some, like Attacker, don't get converted to risk events)
            if not RiskEvent.ignore_observable(observable):
                if self.matches_observable(observable):
                    # TODO: Sanity check since we don't know yet if this is True
                    if matched_observable is not None:
                        raise ValueError(
                            "Unexpected conditon: we don't expect the value corresponding to an "
                            "observables field name to be repeated"
                        )
                    # NOTE: we explicitly do not break early as we want to check each observable
                    matched_observable = observable

        # Ensure we were able to match the risk event to a specific observable
        if matched_observable is None:
            raise ValidationFailed(
                f"Unable to match risk event ({self.risk_object}, {self.risk_object_type}) to an "
                "appropriate observable"
            )

        # Cache and return the matched observable
        self._matched_observable = matched_observable
        return self._matched_observable
