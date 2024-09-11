import uuid
from typing import Any, ClassVar
import json
import hashlib

from pydantic import BaseModel, Field, PrivateAttr, computed_field


class DetectionStanza(BaseModel):
    """
    A model representing a stanza for a detection in savedsearches.conf
    """
    # The lines that comprise this stanza, in the order they appear in the conf
    lines: list[str] = Field(...)

    # The full name of the detection (e.g. "ESCU - My Detection - Rule")
    name: str = Field(...)

    # The metadata extracted from the stanza
    _metadata: dict[str, Any] = PrivateAttr(default={})

    # The key prefix indicating the metadata attribute
    METADATA_LINE_PREFIX: ClassVar[str] = "action.correlationsearch.metadata = "

    def model_post_init(self, __context: Any) -> None:
        super().model_post_init(__context)
        self._parse_metadata()

    def _parse_metadata(self) -> None:
        """
        Using the provided lines, parse out the metadata
        """
        # Set a variable to store the metadata line in
        meta_line: str | None = None

        # Iterate over the lines to look for the metadata line
        for line in self.lines:
            if line.startswith(DetectionStanza.METADATA_LINE_PREFIX):
                # If we find a matching line more than once, we've hit an error
                if meta_line is not None:
                    raise Exception(
                        f"Metadata for detection '{self.name}' found twice in stanza."
                    )
                meta_line = line

        # Report if we could not find the metadata line
        if meta_line is None:
            raise Exception(f"No metadata for detection '{self.name}' found in stanza.")

        # Try to load the metadata JSON into a dict
        try:
            self._metadata: dict[str, Any] = json.loads(meta_line[len(DetectionStanza.METADATA_LINE_PREFIX):])
        except json.decoder.JSONDecodeError as e:
            raise Exception(
                f"Malformed metdata for detection '{self.name}': {e}"
            )

    @computed_field
    @property
    def deprecated(self) -> int:
        """
        An int indicating whether the detection is deprecated
        :returns: int
        """
        return int(self._metadata["deprecated"])

    @computed_field
    @property
    def detection_id(self) -> uuid.UUID:
        """
        A UUID identifying the detection
        :returns: UUID
        """
        return uuid.UUID(self._metadata["detection_id"])

    @computed_field
    @property
    def detection_version(self) -> int:
        """
        The version of the detection
        :returns: int
        """
        return int(self._metadata["detection_version"])

    @computed_field
    @property
    def publish_time(self) -> float:
        """
        The time the detection was published
        :returns: float
        """
        return self._metadata["publish_time"]

    @computed_field
    @property
    def hash(self) -> str:
        """
        The SHA256 hash of the lines of the stanza, excluding the metadata line
        :returns: str (hexdigest)
        """
        hash = hashlib.sha256()
        for line in self.lines:
            if not line.startswith(DetectionStanza.METADATA_LINE_PREFIX):
                hash.update(line.encode("utf-8"))
        return hash.hexdigest()

    def version_should_be_bumped(self, previous: "DetectionStanza") -> bool:
        """
        A helper method that compares this stanza against the same stanza from a previous build;
        returns True if the version still needs to be bumped (e.g. the detection was changed but
        the version was not), False otherwise.
        :param previous: the previous build's DetectionStanza for comparison
        :returns: True if the version still needs to be bumped
        """
        return (self.hash != previous.hash) and (self.detection_version <= previous.detection_version)
