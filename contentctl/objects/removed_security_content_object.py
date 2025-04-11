from __future__ import annotations

import pathlib
from functools import cached_property

from pydantic import ConfigDict, HttpUrl, computed_field, field_validator

from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import (
    SecurityContentObject_Abstract,
)
from contentctl.objects.enums import ContentStatus


class SecurityContentObject(SecurityContentObject_Abstract):
    pass


class RemovedSecurityContentObject(SecurityContentObject):
    # We MUST allow extra fields here because the python definitions of the underlying
    # objects can change. We do not want to throw pasing errors on any of these, but we will
    # only expose fields that are defined in the SecurityContentObject definiton directly
    model_config = ConfigDict(validate_default=True, extra="ignore")
    status: ContentStatus

    @field_validator("status", mode="after")
    @classmethod
    def NarrowStatus(cls, status: ContentStatus) -> ContentStatus:
        return cls.NarrowStatusTemplate(status, [ContentStatus.removed])

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
        # link = f"https://research.splunk.com/migration_guide/{self.id}"
        # This can likely be dynamically generated per detection, but for now we
        # just make it static
        link = "https://research.splunk.com/migration_guide/"

        return HttpUrl(url=link)  # type: ignore

    @classmethod
    def containing_folder(cls) -> pathlib.Path:
        return pathlib.Path("removed")
