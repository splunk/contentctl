from __future__ import annotations

import datetime
import pathlib
from csv import DictWriter
from functools import cached_property
from typing import TYPE_CHECKING

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    computed_field,
    field_validator,
)
from semantic_version import Version

from contentctl.objects.baseline import Baseline
from contentctl.objects.config import CustomApp
from contentctl.objects.detection import Detection
from contentctl.objects.enums import SecurityContentType

if TYPE_CHECKING:
    from contentctl.objects.security_content_object import SecurityContentObject


class DeprecatedSecurityContentObject(SecurityContentObject):
    # We MUST allow extra fields here because the python definitions of the underlying
    # objects can change. We do not want to throw pasing errors on any of these, but we will
    # only expose fields that are defined in the SecurityContentObject definiton directly
    model_config = ConfigDict(validate_default=True, extra="ignore")

    @field_validator("deprecation_info", mode="after")
    def ensure_deprecation_info_is_not_none(self):
        if self.deprecation_info is None:
            raise ValueError(
                "DeprecatedSecurityObject does not define a valid deprecation_info object."
            )
        return self


class DeprecationInfo(BaseModel):
    deprecation_date: datetime.date = Field(
        ...,
        description="On what expected date will this content be deprecated? "
        "If an app is built after this date and attempts to write out this content, an exception will be generated.",
    )
    deprecation_version: Version = Field(
        ...,
        description="In which version of the app was this content deprecated? "
        "If an app is built on or after this version and contains this content, an exception will be generated.",
    )
    reason: str = Field(
        ...,
        description="An explanation of why this content was deprecated.",
        min_length=10,
    )
    replacement_content: list[SecurityContentObject] = Field(
        [],
        description="A list of 0 to N pieces of content that replace this deprecated piece of content. "
        "It is possible that the type(s) of the replacement content may be different than the replaced content. "
        "For example, a detection may be replaced by a story or a macro may be replaced by a lookup.",
    )

    content_type: SecurityContentType = Field(
        description="The type of this object. This must be logged separately because, "
        "as the Python Object definitions change, we may not be able to continue "
        "determining the type of an object based on the presence of values of its fields."
    )

    @computed_field
    @cached_property
    def migration_guide(self) -> HttpUrl:
        """
        A link to the research site containing a migration guide for the content

        :returns: URL to the research site
        :rtype: HTTPUrl
        """

        return HttpUrl(url=f"https://research.splunk.com/migration_guide/{self.id}")  # type: ignore

    @staticmethod
    def writeDeprecationCSV(
        deprecated_content: list[DeprecatedSecurityContentObject],
        app: CustomApp,
        output_file: pathlib.Path,
    ):
        deprecation_rows: list[dict[str, str]] = []
        for content in deprecated_content:
            if content.deprecation_info is None:
                raise Exception(
                    f"Cannot compute deprecation info for {content.name} - object has no deprecation info"
                )
            content.deprecation_info.generateDeprecationLookupRow(content, app)

        with open(output_file, "w") as deprecation_csv_file:
            deprecation_csv_writer = DictWriter(
                deprecation_csv_file,
                fieldnames=[
                    "Name",
                    "ID",
                    "Content Type",
                    "Deprecation Date",
                    "Deprecation Version",
                    "Reason",
                    "Migration Guide",
                    "Replacement Content",
                ],
            )
            deprecation_csv_writer.writeheader()
            deprecation_csv_writer.writerows(deprecation_rows)

    def generateDeprecationLookupRow(
        self, object: DeprecatedSecurityContentObject, app: CustomApp
    ) -> dict[str, str]:
        """
        This function exists as a bit of a shim because pieces of content are identified in ESCU by
        their Stanza name, which could be different than
        """
        if self.content_type == SecurityContentType.detections:
            content_name = Detection.static_get_conf_stanza_name(object.name, app)
        elif self.content_type == SecurityContentType.stories:
            content_name = object.name
        elif self.content_type == SecurityContentType.baselines:
            content_name = Baseline.static_get_conf_stanza_name(object.name, app)

        else:
            raise Exception(
                f"{self.content_type} deprecation is not supported at this time."
            )

        return {
            "Name": content_name,
            "ID": str(object.id),
            "Content Type": self.content_type.name,
            "Deprecation Date": str(self.deprecation_date),
            "Deprecation Version": str(self.deprecation_version),
            "Reason": "Give a unique reason in the model here",
            "Migration Guide": str(self.migration_guide),
            "Replacement Content": "\n".join(
                [str(content.researchSiteLink) for content in self.replacement_content]
            ),
        }
