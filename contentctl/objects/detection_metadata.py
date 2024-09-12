import uuid
from typing import Any

from pydantic import BaseModel, Field, field_validator


class DetectionMetadata(BaseModel):
    """
    A model of the metadata line in a detection stanza in savedsearches.conf
    """
    # A bool indicating whether the detection is deprecated (serialized as an int, 1 or 0)
    deprecated: bool = Field(...)

    # A UUID identifying the detection
    detection_id: uuid.UUID = Field(...)

    # The version of the detection
    detection_version: int = Field(...)

    # The time the detection was published. **NOTE** This field was added to the metadata in ESCU
    # as of v4.39.0
    publish_time: float = Field(...)

    class Config:
        # Allowing for future fields that may be added to the metadata JSON
        extra = "allow"

    @field_validator("deprecated", mode="before")
    @classmethod
    def validate_deprecated(cls, v: Any) -> Any:
        """
        Convert str to int, and then ints to bools for deprecated; raise if not 0 or 1 in the case
        of an int, or if str cannot be converted to int.

        :param v: the value passed
        :type v: :class:`typing.Any`

        :returns: the value
        :rtype: :class:`typing.Any`
        """
        if isinstance(v, str):
            try:
                v = int(v)
            except ValueError as e:
                raise ValueError(f"Cannot convert str value ({v}) to int: {e}") from e
        if isinstance(v, int):
            if not (0 <= v <= 1):
                raise ValueError(
                    f"Value for field 'deprecated' ({v}) must be 0 or 1, if not a bool."
                )
            v = bool(v)
        return v

    @field_validator("detection_version", mode="before")
    @classmethod
    def validate_detection_version(cls, v: Any) -> Any:
        """
        Convert str to int; raise if str cannot be converted to int.

        :param v: the value passed
        :type v: :class:`typing.Any`

        :returns: the value
        :rtype: :class:`typing.Any`
        """
        if isinstance(v, str):
            try:
                v = int(v)
            except ValueError as e:
                raise ValueError(f"Cannot convert str value ({v}) to int: {e}") from e
        return v
