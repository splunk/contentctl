from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contentctl.objects.config import validate

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    FilePath,
    HttpUrl,
    ValidationInfo,
    field_validator,
)


class TestAttackData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data: HttpUrl | FilePath = Field(...)
    # TODO - should source and sourcetype should be mapped to a list
    # of supported source and sourcetypes in a given environment?
    source: str = Field(...)
    sourcetype: str = Field(...)
    custom_index: str | None = None
    host: str | None = None

    @field_validator("data", mode="after")
    @classmethod
    def check_for_existence_of_attack_data_repo(
        cls, value: HttpUrl | FilePath, info: ValidationInfo
    ) -> HttpUrl | FilePath:
        # this appears to be called more than once, the first time
        # info.context is always None. In this case, just return what
        # was passed.
        if not info.context:
            return value

        # When the config is passed, used it to determine if we can map
        # the test data to a file on disk
        if info.context.get("config", None):
            config: validate = info.context.get("config", None)
            return config.map_to_attack_data_cache(value, verbose=config.verbose)
        else:
            raise ValueError(
                "config not passed to TestAttackData constructor in context"
            )
