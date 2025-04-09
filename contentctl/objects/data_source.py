from __future__ import annotations

import pathlib
from typing import Any, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_serializer

from contentctl.objects.enums import ContentStatus
from contentctl.objects.security_content_object import SecurityContentObject


class TA(BaseModel):
    name: str
    url: HttpUrl | None = None
    version: str


class DataSource(SecurityContentObject):
    source: str = Field(...)
    sourcetype: str = Field(...)
    separator: Optional[str] = None
    separator_value: None | str = None
    configuration: Optional[str] = None
    supported_TA: list[TA] = []
    fields: None | list = None
    field_mappings: None | list = None
    mitre_components: list[str] = []
    convert_to_log_source: None | list = None
    example_log: None | str = None
    output_fields: list[str] = []
    status: ContentStatus = ContentStatus.production

    @field_validator("status", mode="after")
    @classmethod
    def NarrowStatus(cls, status: ContentStatus) -> ContentStatus:
        return cls.NarrowStatusTemplate(status, [ContentStatus.production])

    @classmethod
    def containing_folder(cls) -> pathlib.Path:
        return pathlib.Path("data_sources")

    @model_serializer
    def serialize_model(self):
        # Call serializer for parent
        super_fields = super().serialize_model()

        # All fields custom to this model
        model: dict[str, Any] = {
            "source": self.source,
            "sourcetype": self.sourcetype,
            "separator": self.separator,
            "configuration": self.configuration,
            "supported_TA": self.supported_TA,
            "fields": self.fields,
            "field_mappings": self.field_mappings,
            "convert_to_log_source": self.convert_to_log_source,
            "example_log": self.example_log,
        }

        # Combine fields from this model with fields from parent
        super_fields.update(model)

        # return the model
        return super_fields
