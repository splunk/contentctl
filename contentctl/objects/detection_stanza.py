from typing import ClassVar
import hashlib
from functools import cached_property

from pydantic import BaseModel, Field, computed_field

from contentctl.objects.detection_metadata import DetectionMetadata


class DetectionStanza(BaseModel):
    """
    A model representing a stanza for a detection in savedsearches.conf
    """
    # The lines that comprise this stanza, in the order they appear in the conf
    lines: list[str] = Field(...)

    # The full name of the detection (e.g. "ESCU - My Detection - Rule")
    name: str = Field(...)

    # The key prefix indicating the metadata attribute
    METADATA_LINE_PREFIX: ClassVar[str] = "action.correlationsearch.metadata = "

    @computed_field
    @cached_property
    def metadata(self) -> DetectionMetadata:
        """
        The metadata extracted from the stanza. Using the provided lines, parse out the metadata

        :returns: the detection stanza's metadata
        :rtype: :class:`contentctl.objects.detection_metadata.DetectionMetadata`
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

        # Parse the metadata JSON into a model
        return DetectionMetadata.model_validate_json(meta_line[len(DetectionStanza.METADATA_LINE_PREFIX):])

    @computed_field
    @cached_property
    def hash(self) -> str:
        """
        The SHA256 hash of the lines of the stanza, excluding the metadata line

        :returns: hexdigest
        :rtype: str
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
        :type previous: :class:`contentctl.objects.detection_stanza.DetectionStanza`

        :returns: True if the version still needs to be bumped
        :rtype: bool
        """
        return (self.hash != previous.hash) and (self.metadata.detection_version <= previous.metadata.detection_version)
