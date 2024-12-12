from __future__ import annotations
from typing import TYPE_CHECKING, Self, Any

if TYPE_CHECKING:
    from contentctl.objects.deployment import Deployment
    from contentctl.objects.security_content_object import SecurityContentObject
    from contentctl.input.director import DirectorOutputDto
    from contentctl.objects.config import CustomApp

from contentctl.objects.enums import AnalyticsType
from contentctl.objects.constants import CONTENTCTL_MAX_STANZA_LENGTH
import abc
import uuid
import datetime
import pprint
from pydantic import (
    BaseModel,
    field_validator,
    Field,
    ValidationInfo,
    FilePath,
    HttpUrl,
    NonNegativeInt,
    ConfigDict,
    model_serializer
)
from typing import Tuple, Optional, List, Union
import pathlib


NO_FILE_NAME = "NO_FILE_NAME"


class SecurityContentObject_Abstract(BaseModel, abc.ABC):
    model_config = ConfigDict(validate_default=True,extra="forbid")
    name: str = Field(...,max_length=99)
    author: str = Field(...,max_length=255)
    date: datetime.date = Field(...)
    version: NonNegativeInt = Field(...)
    id: uuid.UUID = Field(...) #we set a default here until all content has a uuid
    description: str = Field(...,max_length=10000)
    file_path: Optional[FilePath] = None
    references: Optional[List[HttpUrl]] = None

    def model_post_init(self, __context: Any) -> None:
        self.ensureFileNameMatchesSearchName()

    @model_serializer
    def serialize_model(self):
        return {
            "name": self.name,
            "author": self.author,
            "date": str(self.date),
            "version": self.version,
            "id": str(self.id),
            "description": self.description,
            "references": [str(url) for url in self.references or []]
        }
    
    
    def check_conf_stanza_max_length(self, stanza_name:str, max_stanza_length:int=CONTENTCTL_MAX_STANZA_LENGTH) -> None:
        if len(stanza_name) > max_stanza_length:
            raise ValueError(f"conf stanza may only be {max_stanza_length} characters, "
                             f"but stanza was actually {len(stanza_name)} characters: '{stanza_name}' ")
    
    @staticmethod
    def objectListToNameList(objects: list[SecurityContentObject]) -> list[str]:
        return [object.getName() for object in objects]

    # This function is overloadable by specific types if they want to redefine names, for example
    # to have the format ESCU - NAME - Rule (config.tag - self.name - Rule)
    def getName(self) -> str:
        return self.name

    @classmethod
    def contentNameToFileName(cls, content_name: str) -> str:
        return content_name \
            .replace(' ', '_') \
            .replace('-', '_') \
            .replace('.', '_') \
            .replace('/', '_') \
            .lower() + ".yml"

    def ensureFileNameMatchesSearchName(self):
        file_name = self.contentNameToFileName(self.name)

        if (self.file_path is not None and file_name != self.file_path.name):
            raise ValueError(
                f"The file name MUST be based off the content 'name' field:\n"
                f"\t- Expected File Name: {file_name}\n"
                f"\t- Actual File Name  : {self.file_path.name}"
            )

        return self

    @field_validator('file_path')
    @classmethod
    def file_path_valid(cls, v: Optional[pathlib.PosixPath], info: ValidationInfo):
        if not v:
            # It's possible that the object has no file path - for example filter macros that are created at runtime
            return v
        if not v.name.endswith(".yml"):
            raise ValueError(
                "All Security Content Objects must be YML files and end in .yml.  The following"
                f" file does not: '{v}'"
            )
        return v

    def getReferencesListForJson(self) -> List[str]:
        return [str(url) for url in self.references or []]

    @classmethod
    def mapNamesToSecurityContentObjects(cls, v: list[str], director: Union[DirectorOutputDto, None]) -> list[Self]:
        if director is not None:
            name_map = director.name_to_content_map
        else:
            name_map = {}

        mappedObjects: list[Self] = []
        mistyped_objects: list[SecurityContentObject_Abstract] = []
        missing_objects: list[str] = []
        for object_name in v:
            found_object = name_map.get(object_name, None)
            if not found_object:
                missing_objects.append(object_name)
            elif not isinstance(found_object, cls):
                mistyped_objects.append(found_object)
            else:
                mappedObjects.append(found_object)

        errors: list[str] = []
        if len(missing_objects) > 0:
            errors.append(f"Failed to find the following '{cls.__name__}': {missing_objects}")
        if len(mistyped_objects) > 0:
            for mistyped_object in mistyped_objects:
                errors.append(
                    f"'{mistyped_object.name}' expected to have type '{cls}', but actually "
                    f"had type '{type(mistyped_object)}'"
                )

        if len(errors) > 0:
            error_string = "\n  - ".join(errors)
            raise ValueError(
                f"Found {len(errors)} issues when resolving references Security Content Object "
                f"names:\n  - {error_string}")

        # Sort all objects sorted by name
        return sorted(mappedObjects, key=lambda o: o.name)

    @staticmethod
    def getDeploymentFromType(typeField: Union[str, None], info: ValidationInfo) -> Deployment:
        if typeField is None:
            raise ValueError("'type:' field is missing from YML.")

        if info.context is None:
            raise ValueError("ValidationInfo.context unexpectedly null")

        director: Optional[DirectorOutputDto] = info.context.get("output_dto", None)
        if not director:
            raise ValueError("Cannot set deployment - DirectorOutputDto not passed to Detection Constructor in context")

        type_to_deployment_name_map = {
            AnalyticsType.TTP: "ESCU Default Configuration TTP",
            AnalyticsType.Hunting: "ESCU Default Configuration Hunting",
            AnalyticsType.Correlation: "ESCU Default Configuration Correlation",
            AnalyticsType.Anomaly: "ESCU Default Configuration Anomaly",
            "Baseline": "ESCU Default Configuration Baseline"
        }
        converted_type_field = type_to_deployment_name_map[typeField]

        # TODO: This is clunky, but is imported here to resolve some circular import errors
        from contentctl.objects.deployment import Deployment

        deployments = Deployment.mapNamesToSecurityContentObjects([converted_type_field], director)
        if len(deployments) == 1:
            return deployments[0]
        elif len(deployments) == 0:
            raise ValueError(
                f"Failed to find Deployment for type '{converted_type_field}' "
                f"from  possible {[deployment.type for deployment in director.deployments]}"
            )
        else:
            raise ValueError(
                f"Found more than 1 ({len(deployments)}) Deployment for type '{converted_type_field}' "
                f"from  possible {[deployment.type for deployment in director.deployments]}"
            )

    @staticmethod
    def get_objects_by_name(
        names_to_find: set[str],
        objects_to_search: list[SecurityContentObject_Abstract]
    ) -> Tuple[list[SecurityContentObject_Abstract], set[str]]:
        raise Exception("get_objects_by_name deprecated")
        found_objects = list(filter(lambda obj: obj.name in names_to_find, objects_to_search))
        found_names = set([obj.name for obj in found_objects])
        missing_names = names_to_find - found_names
        return found_objects, missing_names

    @staticmethod
    def create_filename_to_content_dict(
        all_objects: list[SecurityContentObject_Abstract]
    ) -> dict[str, SecurityContentObject_Abstract]:
        name_dict: dict[str, SecurityContentObject_Abstract] = dict()
        for object in all_objects:
            # If file_path is None, this function has been called on an inappropriate
            # SecurityContentObject (e.g. filter macros that are created at runtime but have no
            # actual file associated)
            if object.file_path is None:
                raise ValueError(f"SecurityContentObject is missing a file_path: {object.name}")
            name_dict[str(pathlib.Path(object.file_path))] = object
        return name_dict

    def __repr__(self) -> str:
        # Just use the model_dump functionality that
        # has already been written. This loses some of the
        # richness where objects reference themselves, but
        # is usable
        m = self.model_dump()
        return pprint.pformat(m, indent=3)

    def __str__(self) -> str:
        return self.__repr__()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SecurityContentObject_Abstract):
            raise Exception(f"SecurityContentObject can only be compared to each other, not to {type(other)}")
        return self.name < other.name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecurityContentObject_Abstract):
            raise Exception(f"SecurityContentObject can only be compared to each other, not to {type(other)}")

        if id(self) == id(other) and self.name == other.name and self.id == other.id:
            # Yes, this is the same object
            return True

        elif id(self) == id(other) or self.name == other.name or self.id == other.id:
            raise Exception(
                "Attempted to compare two SecurityContentObjects, but their fields indicate they "
                "were not globally unique:"
                f"\n\tid(obj1)  : {id(self)}"
                f"\n\tid(obj2)  : {id(other)}"
                f"\n\tobj1.name : {self.name}"
                f"\n\tobj2.name : {other.name}"
                f"\n\tobj1.id   : {self.id}"
                f"\n\tobj2.id   : {other.id}"
            )
        else:
            return False

    def __hash__(self) -> NonNegativeInt:
        return id(self)
