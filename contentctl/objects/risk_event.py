import re
from functools import cached_property

from pydantic import Field, PrivateAttr, computed_field, field_validator

from contentctl.objects.base_security_event import BaseSecurityEvent
from contentctl.objects.detection import Detection
from contentctl.objects.errors import ValidationFailed
from contentctl.objects.rba import RiskObject


class RiskEvent(BaseSecurityEvent):
    """Model for risk event in ES"""

    # The subject of the risk event (e.g. a username, process name, system name, account ID, etc.)
    # (not to be confused w/ the risk object from the detection)
    es_risk_object: int | str = Field(alias="risk_object")

    # The type of the risk object from ES (e.g. user, system, or other) (not to be confused w/
    # the risk object from the detection)
    es_risk_object_type: str = Field(alias="risk_object_type")

    # The level of risk associated w/ the risk event
    risk_score: int

    # The message for the risk event
    risk_message: str

    # The analytic stories applicable to this risk event
    analyticstories: list[str] = Field(default=[])

    # The MITRE ATT&CK IDs
    annotations_mitre_attack: list[str] = Field(
        alias="annotations.mitre_attack", default=[]
    )

    # Contributing events search query (we use this to derive the corresponding field from the
    # detection's risk object definition)
    contributing_events_search: str

    # Private attribute caching the risk object this RiskEvent is mapped to
    _matched_risk_object: RiskObject | None = PrivateAttr(default=None)

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
        event(s). Useful for mapping back to a risk object in the detection.
        """
        pattern = re.compile(
            r"\| savedsearch \""
            + self.search_name
            + r"\" \| search (?P<field>[^=]+)=.+"
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

        # Ensure the rba object is defined
        if detection.rba is None:
            raise ValidationFailed(
                f"Unexpected error: Detection '{detection.name}' has no RBA objects associated "
                "with it; cannot validate."
            )

        # Check several conditions against the detection's risk objects
        self.validate_risk_against_risk_objects(detection.rba.risk_objects)

    def validate_mitre_ids(self, detection: Detection) -> None:
        """
        Given the associated detection, validate the risk event's MITRE attack IDs
        :param detection: the detection associated w/ this risk event
        :raises: ValidationFailed
        """
        if sorted(self.annotations_mitre_attack) != sorted(
            detection.tags.mitre_attack_id
        ):
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
        detection_analytic_story = [
            story.name for story in detection.tags.analytic_story
        ]
        if sorted(self.analyticstories) != sorted(detection_analytic_story):
            raise ValidationFailed(
                f"Analytic stories in risk event ({self.analyticstories}) do not match those"
                f" in detection ({[x.name for x in detection.tags.analytic_story]})."
            )

    def validate_risk_message(self, detection: Detection) -> None:
        """
        Given the associated detection, validate the risk event's message
        :param detection: the detection associated w/ this risk event
        :raises: ValidationFailed
        """
        # Ensure the rba object is defined
        if detection.rba is None:
            raise ValidationFailed(
                f"Unexpected error: Detection '{detection.name}' has no RBA objects associated "
                "with it; cannot validate."
            )

        # Extract the field replacement tokens ("$...$")
        field_replacement_pattern = re.compile(r"\$\S+\$")
        tokens = field_replacement_pattern.findall(detection.rba.message)

        # TODO (#346): could expand this to get the field values from the raw events and check
        #   to see that allexpected strings ARE in the risk message (as opposed to checking only
        #   that unexpected strings aren't)
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
            field_replacement_pattern.sub(tmp_placeholder, detection.rba.message)
        )
        placeholder_replacement_pattern = re.compile(tmp_placeholder)
        final_risk_message_pattern = re.compile(
            placeholder_replacement_pattern.sub(
                r"[\\s\\S]*\\S[\\s\\S]*", escaped_source_message_with_placeholder
            )
        )

        # Check created regex pattern againt the observed risk message
        if final_risk_message_pattern.match(self.risk_message) is None:
            raise ValidationFailed(
                "Risk message in event does not match the pattern set by the detection. Message in "
                f'risk event: "{self.risk_message}". Message in detection: '
                f'"{detection.rba.message}".'
            )

    def validate_risk_against_risk_objects(self, risk_objects: set[RiskObject]) -> None:
        """
        Given the risk objects from the associated detection, validate the risk event against those
        risk objects
        :param risk_objects: the risk objects from the detection
        :raises: ValidationFailed
        """
        # Get the matched risk object; will raise validation errors if no match can be made or if
        # risk is missing values associated w/ risk objects
        matched_risk_object = self.get_matched_risk_object(risk_objects)

        # The risk object type from the risk event should match our mapping of internal risk object
        # types
        if self.es_risk_object_type != matched_risk_object.type.value:
            raise ValidationFailed(
                f"The risk object type from the risk event ({self.es_risk_object_type}) does not match"
                " the expected type based on the matched risk object "
                f"({matched_risk_object.type.value}): risk event=(object={self.es_risk_object}, "
                f"type={self.es_risk_object_type}, source_field_name={self.source_field_name}), "
                f"risk object=(name={matched_risk_object.field}, "
                f"type={matched_risk_object.type.value})"
            )

        # Check risk_score
        if self.risk_score != matched_risk_object.score:
            raise ValidationFailed(
                f"Risk score observed in risk event ({self.risk_score}) does not match risk score in "
                f"matched risk object from detection ({matched_risk_object.score})."
            )

    def get_matched_risk_object(self, risk_objects: set[RiskObject]) -> RiskObject:
        """
        Given a set of risk objects, return the one this risk event matches
        :param risk_objects: the list of risk objects we are checking against
        :returns: the matched risk object
        :raises ValidationFailed: if a match could not be made or if an expected field (based on
            one of the risk objects) could not be found in the risk event
        """
        # Return the cached match if already found
        if self._matched_risk_object is not None:
            return self._matched_risk_object

        matched_risk_object: RiskObject | None = None

        # Iterate over the obervables and check for a match
        for risk_object in risk_objects:
            # TODO (#252): Refactor and re-enable per-field validation of risk events
            # Each the field name used in each risk object shoud be present in the risk event
            # if not hasattr(self, risk_object.field):
            #     raise ValidationFailed(
            #         f"Risk object field \"{risk_object.field}\" not found in risk event."
            #     )

            # Try to match the risk_object against a specific risk object
            if self.source_field_name == risk_object.field:
                # TODO (#347): enforce that field names are not repeated across risk objects as
                #   part of build/validate
                if matched_risk_object is not None:
                    raise ValueError(
                        "Unexpected conditon: we don't expect multiple risk objects to use the "
                        "same field name, so we should not be able match the risk event to "
                        "multiple risk objects."
                    )

                # NOTE: we explicitly do not break early as we want to check each risk object
                matched_risk_object = risk_object

        # Ensure we were able to match the risk event to a specific risk object
        if matched_risk_object is None:
            raise ValidationFailed(
                f"Unable to match risk event (object={self.es_risk_object}, type="
                f"{self.es_risk_object_type}, source_field_name={self.source_field_name}) to a "
                "risk object in the detection; please check for errors in the risk object types for this "
                "detection, as well as the risk event build process in contentctl (e.g. threat "
                "objects aren't being converted to risk objects somehow)."
            )

        # Cache and return the matched risk object
        self._matched_risk_object = matched_risk_object
        return self._matched_risk_object
