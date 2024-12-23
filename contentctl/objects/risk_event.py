import re
from functools import cached_property

from pydantic import ConfigDict, BaseModel, Field, PrivateAttr, field_validator, computed_field
from contentctl.objects.errors import ValidationFailed
from contentctl.objects.detection import Detection
from contentctl.objects.observable import Observable

# TODO (#259): Map our observable types to more than user/system
# TODO (#247): centralize this mapping w/ usage of SES_OBSERVABLE_TYPE_MAPPING (see
#   observable.py) and the ad hoc mapping made in detection_abstract.py (see the risk property func)
TYPE_MAP: dict[str, list[str]] = {
    "system": [
        "Hostname",
        "IP Address",
        "Endpoint"
    ],
    "user": [
        "User",
        "User Name",
        "Email Address",
        "Email"
    ],
    "hash_values": [],
    "network_artifacts": [],
    "host_artifacts": [],
    "tools": [],
    "other": [
        "Process",
        "URL String",
        "Unknown",
        "Process Name",
        "MAC Address",
        "File Name",
        "File Hash",
        "Resource UID",
        "Uniform Resource Locator",
        "File",
        "Geo Location",
        "Container",
        "Registry Key",
        "Registry Value",
        "Other"
    ]
}

# Roles that should not generate risks
IGNORE_ROLES: list[str] = ["Attacker"]


class RiskEvent(BaseModel):
    """Model for risk event in ES"""

    # The search name (e.g. "ESCU - Windows Modify Registry EnableLinkedConnections - Rule")
    search_name: str

    # The subject of the risk event (e.g. a username, process name, system name, account ID, etc.)
    risk_object: int | str

    # The type of the risk object (e.g. user, system, or other)
    risk_object_type: str

    # The level of risk associated w/ the risk event
    risk_score: int

    # The search ID that found that generated this risk event
    orig_sid: str

    # The message for the risk event
    risk_message: str

    # The analytic stories applicable to this risk event
    analyticstories: list[str] = Field(default=[])

    # The MITRE ATT&CK IDs
    annotations_mitre_attack: list[str] = Field(
        alias="annotations.mitre_attack",
        default=[]
    )

    # Contributing events search query (we use this to derive the corresponding field from the
    # observables)
    contributing_events_search: str

    # Private attribute caching the observable this RiskEvent is mapped to
    _matched_observable: Observable | None = PrivateAttr(default=None)

    # Allowing fields that aren't explicitly defined to be passed since some of the risk event's
    # fields vary depending on the SPL which generated them
    model_config = ConfigDict(
        extra="allow"
    )

    @field_validator("annotations_mitre_attack", "analyticstories", mode="before")
    @classmethod
    def _convert_str_value_to_singleton(cls, v: str | list[str]) -> list[str]:
        """
        Given a value, determine if its a list or a single str value; if a single value, return as a
        singleton. Do nothing if anything else.
        """
        if isinstance(v, list):
            return v
        else:
            return [v]

    @computed_field
    @cached_property
    def source_field_name(self) -> str:
        """
        A cached derivation of the source field name the risk event corresponds to in the relevant
        event(s). Useful for mapping back to an observable in the detection.
        """
        pattern = re.compile(
            r"\| savedsearch \"" + self.search_name + r"\" \| search (?P<field>[^=]+)=.+"
        )
        match = pattern.search(self.contributing_events_search)
        if match is None:
            raise ValueError(
                "Unable to parse source field name from risk event using "
                f"'contributing_events_search' ('{self.contributing_events_search}') using "
                f"pattern: {pattern}"
            )
        return match.group("field")

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

        # Check several conditions against the observables
        self.validate_risk_against_observables(detection.tags.observable)

    def validate_mitre_ids(self, detection: Detection) -> None:
        """
        Given the associated detection, validate the risk event's MITRE attack IDs
        :param detection: the detection associated w/ this risk event
        :raises: ValidationFailed
        """
        if sorted(self.annotations_mitre_attack) != sorted(detection.tags.mitre_attack_id):
            raise ValidationFailed(
                f"MITRE ATT&CK IDs in risk event ({self.annotations_mitre_attack}) do not match those"
                f" in detection ({detection.tags.mitre_attack_id})."
            )

    def validate_analyticstories(self, detection: Detection) -> None:
        """
        Given the associated detection, validate the risk event's MITRE analytic stories
        :param detection: the detection associated w/ this risk event
        :raises: ValidationFailed
        """
        # Render the detection analytic_story to a list of strings before comparing
        detection_analytic_story = [story.name for story in detection.tags.analytic_story]
        if sorted(self.analyticstories) != sorted(detection_analytic_story):
            raise ValidationFailed(
                f"Analytic stories in risk event ({self.analyticstories}) do not match those"
                f" in detection ({detection.tags.analytic_story})."
            )

    def validate_risk_message(self, detection: Detection) -> None:
        """
        Given the associated detection, validate the risk event's message
        :param detection: the detection associated w/ this risk event
        :raises: ValidationFailed
        """
        # Extract the field replacement tokens ("$...$")
        field_replacement_pattern = re.compile(r"\$\S+\$")
        tokens = field_replacement_pattern.findall(detection.tags.message)

        # Check for the presence of each token in the message from the risk event
        for token in tokens:
            if token in self.risk_message:
                raise ValidationFailed(
                    f"Unreplaced field replacement string ('{token}') found in risk message:"
                    f" {self.risk_message}"
                )

        # Convert detection source message to regex pattern; we need to first sub in a placeholder
        # so we can escape the string, and then swap in the actual regex elements in place of the
        # placeholder
        tmp_placeholder = "PLACEHOLDERPATTERNFORESCAPING"
        escaped_source_message_with_placeholder: str = re.escape(
            field_replacement_pattern.sub(
                tmp_placeholder,
                detection.tags.message
            )
        )
        placeholder_replacement_pattern = re.compile(tmp_placeholder)
        final_risk_message_pattern = re.compile(
            placeholder_replacement_pattern.sub(
                r"[\\s\\S]*\\S[\\s\\S]*",
                escaped_source_message_with_placeholder
            )
        )

        # Check created regex pattern againt the observed risk message
        if final_risk_message_pattern.match(self.risk_message) is None:
            raise ValidationFailed(
                "Risk message in event does not match the pattern set by the detection. Message in "
                f"risk event: \"{self.risk_message}\". Message in detection: "
                f"\"{detection.tags.message}\"."
            )

    def validate_risk_against_observables(self, observables: list[Observable]) -> None:
        """
        Given the observables from the associated detection, validate the risk event against those
        observables
        :param observables: the Observable objects from the detection
        :raises: ValidationFailed
        """
        # Get the matched observable; will raise validation errors if no match can be made or if
        # risk is missing values associated w/ observables
        matched_observable = self.get_matched_observable(observables)

        # The risk object type should match our mapping of observable types to risk types
        expected_type = RiskEvent.observable_type_to_risk_type(matched_observable.type)
        if self.risk_object_type != expected_type:
            raise ValidationFailed(
                f"The risk object type ({self.risk_object_type}) does not match the expected type "
                f"based on the matched observable ({matched_observable.type}->{expected_type}): "
                f"risk=(object={self.risk_object}, type={self.risk_object_type}, "
                f"source_field_name={self.source_field_name}), "
                f"observable=(name={matched_observable.name}, type={matched_observable.type}, "
                f"role={matched_observable.role})"
            )

    @staticmethod
    def observable_type_to_risk_type(observable_type: str) -> str:
        """
        Given a string representing the observable type, use our mapping to convert it to the
        expected type in the risk event
        :param observable_type: the type of the observable
        :returns: a string (the risk object type)
        :raises ValueError: if the observable type has not yet been mapped to a risk object type
        """
        # Iterate over the map and search the lists for a match
        for risk_type in TYPE_MAP:
            if observable_type in TYPE_MAP[risk_type]:
                return risk_type

        raise ValueError(
            f"Observable type {observable_type} does not have a mapping to a risk type in TYPE_MAP"
        )

    @staticmethod
    def ignore_observable(observable: Observable) -> bool:
        """
        Given an observable, determine based on its roles if it should be ignored in risk/observable
        matching (e.g. Attacker role observables should not generate risk events)
        :param observable: the Observable object we are checking the roles of
        :returns: a bool indicating whether this observable should be ignored or not
        """
        ignore = False
        for role in observable.role:
            if role in IGNORE_ROLES:
                ignore = True
                break
        return ignore

    def get_matched_observable(self, observables: list[Observable]) -> Observable:
        """
        Given a list of observables, return the one this risk event matches
        :param observables: the list of Observable objects we are checking against
        :returns: the matched Observable object
        :raises ValidationFailed: if a match could not be made or if an expected field (based on
            one of the observables) could not be found in the risk event
        """
        # Return the cached match if already found
        if self._matched_observable is not None:
            return self._matched_observable

        matched_observable: Observable | None = None

        # Iterate over the obervables and check for a match
        for observable in observables:
            # TODO (#252): Refactor and re-enable per-field validation of risk events
            # Each the field name used in each observable shoud be present in the risk event
            # if not hasattr(self, observable.name):
            #     raise ValidationFailed(
            #         f"Observable field \"{observable.name}\" not found in risk event."
            #     )

            # Try to match the risk_object against a specific observable for the obervables with
            # a valid role (some, like Attacker, shouldn't get converted to risk events)
            if self.source_field_name == observable.name:
                if matched_observable is not None:
                    raise ValueError(
                        "Unexpected conditon: we don't expect the source event field "
                        "corresponding to an observables field name to be repeated."
                    )

                # Report any risk events we find that shouldn't be there
                if RiskEvent.ignore_observable(observable):
                    raise ValidationFailed(
                        "Risk event matched an observable with an invalid role: "
                        f"(name={observable.name}, type={observable.type}, role={observable.role})")
                # NOTE: we explicitly do not break early as we want to check each observable
                matched_observable = observable

        # Ensure we were able to match the risk event to a specific observable
        if matched_observable is None:
            raise ValidationFailed(
                f"Unable to match risk event (object={self.risk_object}, type="
                f"{self.risk_object_type}, source_field_name={self.source_field_name}) to an "
                "observable; please check for errors in the observable roles/types for this "
                "detection, as well as the risk event build process in contentctl."
            )

        # Cache and return the matched observable
        self._matched_observable = matched_observable
        return self._matched_observable
