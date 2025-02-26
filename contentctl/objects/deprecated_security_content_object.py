from __future__ import annotations

import pathlib
from functools import cached_property
from typing import Any

from pydantic import ConfigDict, HttpUrl, computed_field, field_validator

from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import (
    SecurityContentObject_Abstract,
)


class SecurityContentObject(SecurityContentObject_Abstract):
    pass


class DeprecatedSecurityContentObject(SecurityContentObject):
    # We MUST allow extra fields here because the python definitions of the underlying
    # objects can change. We do not want to throw pasing errors on any of these, but we will
    # only expose fields that are defined in the SecurityContentObject definiton directly
    model_config = ConfigDict(validate_default=True, extra="ignore")

    @field_validator("deprecation_info")
    def ensure_deprecation_info_is_not_none(cls, deprecation_info: Any) -> Any:
        return deprecation_info
        if deprecation_info is None:
            raise ValueError(
                "DeprecatedSecurityObject does not define a valid deprecation_info object."
            )
        return deprecation_info

    @computed_field
    @cached_property
    def migration_guide(self) -> HttpUrl:
        """
        A link to the research site containing a migration guide for the content

        :returns: URL to the research site
        :rtype: HTTPUrl
        """
        # this is split up so that we can explicilty ignore the warning on constructing
        # the HttpUrl but catch other type issues
        link = f"https://research.splunk.com/migration_guide/{self.id}"

        return HttpUrl(url=link)  # type: ignore

    @classmethod
    def containing_folder(cls) -> pathlib.Path:
        return pathlib.Path("deprecated/content")

    '''
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
            content.generateDeprecationLookupRow(content, app)

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

    
    def generateDeprecationLookupRow(self, app: CustomApp) -> dict[str, str]:
        """
        This function exists as a bit of a shim because pieces of content are identified in ESCU by
        their Stanza name, which could be different than
        """
        if self.deprecation_info is None:
            raise ValueError(
                f"DeprecatedSecurityContentObject 'deprecation_info' field was None for '{self.name}' in file '{self.file_path}'"
            )

        if self.deprecation_info.content_type == SecurityContentType.detection:
            from contentctl.objects.detection import Detection

            content_name = Detection.static_get_conf_stanza_name(self.name, app)
        elif self.deprecation_info.content_type == SecurityContentType.story:
            content_name = self.name
        elif self.deprecation_info.content_type == SecurityContentType.baseline:
            from contentctl.objects.baseline import Baseline

            content_name = Baseline.static_get_conf_stanza_name(self.name, app)

        else:
            raise Exception(
                f"{self.deprecation_info.content_type} deprecation is not supported at this time."
            )

        return {
            "Name": content_name,
            "ID": str(self.id),
            "Content Type": self.deprecation_info.content_type.name,
            "Deprecation Date": str(self.deprecation_info.deprecation_date),
            "Deprecation Version": str(self.deprecation_info.deprecation_version),
            "Reason": "Give a unique reason in the model here",
            "Migration Guide": str(self.migration_guide),
            "Replacement Content": "\n".join(
                [
                    str(content.researchSiteLink)
                    for content in self.deprecation_info.replacement_content
                ]
            ),
        }
        '''
