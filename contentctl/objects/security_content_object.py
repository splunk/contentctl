from __future__ import annotations
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import (
    SecurityContentObject_Abstract,
)
import datetime
from pydantic import Field, HttpUrl, computed_field
from semantic_version import Version
from functools import cached_property
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.detection import Detection

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.config import CustomApp

class SecurityContentObject(SecurityContentObject_Abstract):
    date: datetime.date = Field(
        ...,
        description="On what expected date will this content be deprecated? "
        "If an app is built after this date and attempts to write out this content, an exception will be generated.",
    )
    version_deprecated: Version = Field(
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

    content_type: SecurityContentType

    @computed_field
    @cached_property
    def migration_guide(self) -> HttpUrl:
        """
        A link to the research site containing a migration guide for the content

        :returns: URL to the research site
        :rtype: HTTPUrl
        """

        return HttpUrl(url=f"https://research.splunk.com/migration_guide/{self.id}")  # type: ignore

    def generateDeprecaitonLookupRow(self, app:CustomApp) -> dict[str, str] | None:
        if self.content_type not in [SecurityContentType.detections]:
            return self.generateDetectionDeprecationLookupRow(app)
        else:
            raise Exception(
                f"{self.content_type} deprecation is not supported at this time."
            )

    def generateDetectionDeprecationLookupRow(self, app:CustomApp) -> dict[str, str]:
        return {
            "Name": Detection.static_get_conf_stanza_name(self.name, app),
            "ID": str(self.id),
            "Content Type": type(self).__name__,
            "Deprecation Date": str(self.date),
            "Reason": "Give a unique reason in the model here",
            "Migration Guide": str(self.migration_guide),
            "Replacements": "\n".join([str(content.researchSiteLink) for content in self.replacement_content])        
        
        }
