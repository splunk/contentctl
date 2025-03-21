from __future__ import annotations

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

    @field_validator("data", mode="before")
    @classmethod
    def check_for_existence_of_attack_data_repo(
        cls, value: HttpUrl | FilePath, info: ValidationInfo
    ) -> HttpUrl | FilePath:
        if info.context and info.context.get("config", None):
            from contentctl.objects.config import validate

            config: validate = info.context.get("config", None)

            # trim off the beginning of the attack data url
            STARTING = (
                "https://media.githubusercontent.com/media/splunk/attack_data/master/"
            )
            if str(value).startswith(STARTING):
                new_path = config.splunk_attack_data_path / str(value).replace(
                    STARTING, ""
                )
                if new_path.is_file():
                    # print("\ngreat we mapped the new path!")

                    return new_path
            else:
                print(f"\n no new path :( - {value}")
        return value
