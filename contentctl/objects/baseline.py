from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, List, Literal

if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto

from pydantic import (
    Field,
    ValidationInfo,
    computed_field,
    field_validator,
    model_serializer,
)

from contentctl.objects.baseline_tags import BaselineTags
from contentctl.objects.config import CustomApp
from contentctl.objects.constants import (
    CONTENTCTL_BASELINE_STANZA_NAME_FORMAT_TEMPLATE,
    CONTENTCTL_MAX_SEARCH_NAME_LENGTH,
)
from contentctl.objects.deployment import Deployment
from contentctl.objects.enums import DataModel, DetectionStatus
from contentctl.objects.lookup import Lookup
from contentctl.objects.security_content_object import SecurityContentObject


class Baseline(SecurityContentObject):
    name: str = Field(..., max_length=CONTENTCTL_MAX_SEARCH_NAME_LENGTH)
    type: Annotated[str, Field(pattern="^Baseline$")] = Field(...)
    search: str = Field(..., min_length=4)
    how_to_implement: str = Field(..., min_length=4)
    known_false_positives: str = Field(..., min_length=4)
    tags: BaselineTags = Field(...)
    lookups: list[Lookup] = Field([], validate_default=True)
    # enrichment
    deployment: Deployment = Field({})
    status: Literal[DetectionStatus.production, DetectionStatus.deprecated]

    @field_validator("lookups", mode="before")
    @classmethod
    def getBaselineLookups(cls, v: list[str], info: ValidationInfo) -> list[Lookup]:
        """
        This function has been copied and renamed from the Detection_Abstract class
        """
        director: DirectorOutputDto = info.context.get("output_dto", None)
        search: str | None = info.data.get("search", None)
        if search is None:
            raise ValueError("Search was None - is this file missing the search field?")

        lookups = Lookup.get_lookups(search, director)
        return lookups

    def get_conf_stanza_name(self, app: CustomApp) -> str:
        stanza_name = CONTENTCTL_BASELINE_STANZA_NAME_FORMAT_TEMPLATE.format(
            app_label=app.label, detection_name=self.name
        )
        self.check_conf_stanza_max_length(stanza_name)
        return stanza_name

    @field_validator("deployment", mode="before")
    def getDeployment(cls, v: Any, info: ValidationInfo) -> Deployment:
        return Deployment.getDeployment(v, info)

    @computed_field
    @property
    def datamodel(self) -> List[DataModel]:
        return [dm for dm in DataModel if dm in self.search]

    @model_serializer
    def serialize_model(self):
        # Call serializer for parent
        super_fields = super().serialize_model()

        # All fields custom to this model
        model = {
            "tags": self.tags.model_dump(),
            "type": self.type,
            "search": self.search,
            "how_to_implement": self.how_to_implement,
            "known_false_positives": self.known_false_positives,
            "datamodel": self.datamodel,
        }

        # Combine fields from this model with fields from parent
        super_fields.update(model)

        # return the model
        return super_fields
