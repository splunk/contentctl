from __future__ import annotations

from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    from contentctl.objects.config import Config_Base, CustomApp
    from contentctl.objects.deployment import Deployment

import abc
import datetime
import pathlib
import pprint
import uuid
from abc import abstractmethod
from csv import DictWriter
from functools import cached_property
from typing import List, Optional, Tuple, Type, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    FilePath,
    HttpUrl,
    NonNegativeInt,
    ValidationInfo,
    computed_field,
    field_validator,
    model_serializer,
    model_validator,
)
from semantic_version import Version

from contentctl.objects.constants import (
    CONTENTCTL_MAX_STANZA_LENGTH,
    DEPRECATED_TEMPLATE,
    EXPERIMENTAL_TEMPLATE,
)
from contentctl.objects.enums import AnalyticsType, DetectionStatus

NO_FILE_NAME = "NO_FILE_NAME"


class DeprecationInfo(BaseModel):
    deprecated_content: SecurityContentObject_Abstract

    deprecated_in_version: str = Field(
        ...,
        description="In which version of the app was this content deprecated? "
        "If an app is built on or after this version and contains this content, an exception will be generated.",
    )

    reason: str = Field(
        ...,
        description="An explanation of why this content was deprecated.",
        min_length=6,
    )
    replacement_content: list[SecurityContentObject_Abstract] = Field(
        [],
        description="A list of 0 to N pieces of content that replace this deprecated piece of content. "
        "It is possible that the type(s) of the replacement content may be different than the replaced content. "
        "For example, a detection may be replaced by a story or a macro may be replaced by a lookup.",
    )

    def enforceDeprecationRequirement(self, cfg: Config_Base) -> None:
        """
        If content is supposed to be deprecated based on the deprecation_version,
        but has NOT been deprecated, this function should throw an Exception indicating that.

        Args:
            cfg (Config_Base): configuration for contentctl built app
        """
        if self.shouldContentBeRemoved(cfg):
            if self.hasContentBeenRemoved(cfg):
                # This is content that has already been removed
                pass
            else:
                raise Exception(
                    f"Content named '{self.deprecated_content.name}' "
                    f"was marked for deprecation in version [{self.deprecated_in_version}]. "
                    f"However, this content is STILL PRESENT in the current build [{cfg.app.version}]. "
                    f"This content should be moved to the folder '{self.deprecated_content.file_path}' into '{cfg.deprecated_content_path}'"
                )
        else:
            if self.hasContentBeenRemoved(cfg):
                raise Exception(
                    f"Content named '{self.deprecated_content.name}' "
                    f"was marked for deprecation in version [{self.deprecated_in_version}]. "
                    f"However, this content is HAS BEEN REMOVED EARLY in the current build [{cfg.app.version}]. "
                    f"This content should be moved out of the folder '{cfg.deprecated_content_path} and into its appropriate content folder.'"
                )
            else:
                # This is content that will be removed in the future
                pass

    def hasContentBeenRemoved(self, cfg: Config_Base) -> bool:
        """
        Determines if a piece of content has actually been removed from the app.
        This is true if a piece of content resides in the REPO_ROOT/deprecated folder.
        A piece of content that lives in detections, even detections/deprecated, has NOT
        actually been removed from the app yet and will be included in a build
        Args:
            cfg (Config_Base): configuration for contentctl built app

        Returns:
            bool: whether or not the content is still included in a build of the app
        """
        if self.deprecated_content.file_path is None:
            raise Exception(
                f"Unable to determine if content {self.deprecated_content.name} "
                f"has been moved into the folder {cfg.deprecated_content_path}. "
                "The content is not backed by a file (content.file_path was 'None')"
            )

        return self.deprecated_content.file_path.resolve().is_relative_to(
            cfg.deprecated_content_path.resolve()
        )

    def shouldContentBeRemoved(self, cfg: Config_Base) -> bool:
        """
        Determines if a piece of content should have been removed from the
        content shipped in the app.  This is true if a piece of deprecated
        content meets one, of both, of the following criteria:
        1. The deprecation date is <= the current date
        2. The deprecation verison is <= the current version
        Args:
            cfg (Config_Base): configuration for contentctl built app

        Returns:
            bool: True or False, based on whether something should be removed from the app
        """
        try:
            deprecation_version = Version(self.deprecated_in_version)
        except Exception as e:
            raise Exception(
                f"Unable to parse deprecation_version info for {self.deprecated_content.name} into a valid Semantic Version: [{self.deprecated_in_version}]: {e}"
            )
        try:
            current_app_version = Version(cfg.app.version)
        except Exception:
            raise Exception(
                f"Unable to parse deprecation_version info for the app {cfg.app.title} into a valid Semantic Version: [{cfg.app.version}]"
            )

        if deprecation_version <= current_app_version:
            return True
        return False

    @field_validator("replacement_content", mode="before")
    @classmethod
    def mapReplacementContent(
        cls, v: list[str], info: ValidationInfo
    ) -> list[SecurityContentObject_Abstract]:
        director: DirectorOutputDto = info.context.get("output_dto", None)
        return SecurityContentObject_Abstract.mapNamesToSecurityContentObjects(
            v, director
        )


class DeprecationDocumentationFile(BaseModel):
    baselines: list[DeprecationInfo]
    dashboards: list[DeprecationInfo] = []
    data_sources: list[DeprecationInfo] = []
    deployments: list[DeprecationInfo] = []
    investigations: list[DeprecationInfo]
    lookups: list[DeprecationInfo] = []
    macros: list[DeprecationInfo] = []
    stories: list[DeprecationInfo]
    detections: list[DeprecationInfo]

    def writeDeprecationCSV(
        self,
        app: CustomApp,
        output_file: pathlib.Path,
    ):
        deprecation_rows: list[dict[str, str]] = []

        for content in self.detections:
            from contentctl.objects.detection import Detection

            deprecation_rows.append(
                self.generateDeprecationLookupRow(content, Detection, app)
            )

        for content in self.baselines:
            from contentctl.objects.baseline import Baseline

            deprecation_rows.append(
                self.generateDeprecationLookupRow(content, Baseline, app)
            )
        for content in self.stories:
            from contentctl.objects.story import Story

            deprecation_rows.append(
                self.generateDeprecationLookupRow(content, Story, app)
            )

        with open(output_file, "w") as deprecation_csv_file:
            deprecation_csv_writer = DictWriter(
                deprecation_csv_file,
                fieldnames=[
                    "Name",
                    "Content Type",
                    "Deprecated in Version",
                    "Reason",
                    "Migration Guide",
                    "Replacement Content",
                ],
            )
            deprecation_csv_writer.writeheader()
            deprecation_csv_writer.writerows(deprecation_rows)

        print(f"Finished generating deprecation CSV at {output_file}")

    def generateDeprecationLookupRow(
        self,
        info: DeprecationInfo,
        contentType: type[SecurityContentObject_Abstract],
        app: CustomApp,
    ) -> dict[str, str]:
        """
        This function exists as a bit of a shim because pieces of content are identified in ESCU by
        their Stanza name, which could be different than
        """

        # For deprecation to be supported for a given object type, the static_get_conf_stanza_name
        # must be defined. It is presently only defined for Detection, Baselines, and Stories, so
        # this is likely something we will need to work on in the future if we plan to deprecate
        # other types of content

        full_content_name: str = contentType.static_get_conf_stanza_name(
            info.deprecated_content.name, app
        )
        return {
            "Name": full_content_name,
            "Content Type": contentType.__name__,
            "Deprecated in Version": str(info.deprecated_in_version),
            "Reason": info.reason,
            # We could compute this dynamically for each
            # piece of content if we wanted
            "Migration Guide": "https://research.splunk.com/migration_guide/",
            "Replacement Content": "\n".join(
                [str(content.researchSiteLink) for content in info.replacement_content]
            ),
        }

    @classmethod
    def mapContent(
        cls,
        v: list[dict[str, Any]],
        info: ValidationInfo,
        contentClass: Type[SecurityContentObject_Abstract],
    ) -> list[SecurityContentObject_Abstract]:
        director: DirectorOutputDto = info.context.get("output_dto", None)
        if not isinstance(v, list):
            raise ValueError(f"Must be a list of DeprecationInfo, not {type(v)}")

        mapping_exceptions: list[Exception] = []
        for elem in v:
            if not isinstance(elem, dict):
                mapping_exceptions.append(
                    ValueError(
                        f"Must be a list DeprecationInfo object, not {type(elem)}"
                    )
                )
            name = elem.get("deprecated_content", None)
            if not isinstance(name, str):
                mapping_exceptions.append(
                    ValueError(f"deprecated_content must be a string, not {type(name)}")
                )
                continue
            try:
                matched_content = contentClass.mapNamesToSecurityContentObjects(
                    [name], director
                )[0]

            except Exception:
                try:
                    from contentctl.objects.deprecated_security_content_object import (
                        DeprecatedSecurityContentObject,
                    )

                    matched_content = DeprecatedSecurityContentObject.mapNamesToSecurityContentObjects(
                        [name], director
                    )[0]
                except Exception:
                    mapping_exceptions.append(
                        ValueError(
                            f"Failed to map content found in deprecated content yml to any content: [{name}]"
                        )
                    )
                    continue
            if matched_content.status not in [
                DetectionStatus.deprecated,
                DetectionStatus.removed,
            ]:
                mapping_exceptions.append(
                    Exception(
                        f"{matched_content.name} is in the deprecation file but the underlying detection is not marked as deprecated"
                    )
                )
                continue
            elem["deprecated_content"] = matched_content

        if len(mapping_exceptions) > 0:
            raise ExceptionGroup(
                "The following Exceptions were generated while parsing the Deprecation Mapping File",
                mapping_exceptions,
            )
        return v

    @model_validator(mode="after")
    def enforceDeprecationRequirements(self, info: ValidationInfo) -> Self:
        config: Config_Base = info.context.get("config", None)
        exceptions: list[Exception] = []
        for content in (
            self.baselines
            + self.dashboards
            + self.data_sources
            + self.deployments
            + self.investigations
            + self.lookups
            + self.macros
            + self.stories
            + self.detections
        ):
            # point the deprecation_info for the object at the deprecation_info that was constructed
            content.deprecated_content.deprecation_info = content

            # Make sure that if the content has been deprecated, it is in the right location
            try:
                content.enforceDeprecationRequirement(config)
            except Exception as e:
                exceptions.append(e)
        if len(exceptions) == 0:
            return self
        raise ExceptionGroup(
            "The following errors we found while enforcing content deprecation requirements.",
            exceptions,
        )

    @field_validator("baselines", mode="before")
    @classmethod
    def mapBaselines(
        cls, v: list[dict[str, Any]], info: ValidationInfo
    ) -> list[SecurityContentObject_Abstract]:
        from contentctl.objects.baseline import Baseline

        return cls.mapContent(v, info, Baseline)

    @field_validator("detections", mode="before")
    @classmethod
    def mapDetections(
        cls, v: list[dict[str, Any]], info: ValidationInfo
    ) -> list[SecurityContentObject_Abstract]:
        from contentctl.objects.detection import Detection

        return cls.mapContent(v, info, Detection)

    @field_validator("stories", mode="before")
    @classmethod
    def mapStories(
        cls, v: list[dict[str, Any]], info: ValidationInfo
    ) -> list[SecurityContentObject_Abstract]:
        from contentctl.objects.story import Story

        return cls.mapContent(v, info, Story)

    @field_validator("investigations", mode="before")
    @classmethod
    def mapInvestigations(
        cls, v: list[dict[str, Any]], info: ValidationInfo
    ) -> list[SecurityContentObject_Abstract]:
        from contentctl.objects.investigation import Investigation

        return cls.mapContent(v, info, Investigation)

    @field_validator(
        "dashboards",
        "data_sources",
        "deployments",
        "lookups",
        "macros",
        mode="before",
    )
    @classmethod
    def mapUnsupportedContent(
        cls, v: list[dict[str, Any]], info: ValidationInfo
    ) -> list[SecurityContentObject_Abstract]:
        if len(v) > 0:
            raise Exception("Deprecation of this content is not yet supported")
        return []


class SecurityContentObject_Abstract(BaseModel, abc.ABC):
    model_config = ConfigDict(validate_default=True, extra="forbid")
    name: str = Field(..., max_length=99)
    author: str = Field(..., max_length=255)
    date: datetime.date = Field(...)
    version: NonNegativeInt = Field(...)
    id: uuid.UUID = Field(...)  # we set a default here until all content has a uuid
    description: str = Field(..., max_length=10000)
    file_path: Optional[FilePath] = None
    references: Optional[List[HttpUrl]] = None
    deprecation_info: DeprecationInfo | None = None

    @classmethod
    @abstractmethod
    def containing_folder(cls) -> pathlib.Path:
        raise NotImplementedError(
            f"Containing folder has not been implemented for {cls.__name__}"
        )

    def model_post_init(self, __context: Any) -> None:
        self.ensureFileNameMatchesSearchName()

    @model_validator(mode="after")
    def validate_deprecation_info(self) -> Self:
        return self
        # Ensure that if the object has a "status" field AND
        # that field is set to deprecated that the deprecation_info
        # field is not None.
        status: None | DetectionStatus = getattr(self, "status", None)
        if status == DetectionStatus.deprecated:
            # This is a detection and the status was defined.
            if self.deprecation_info is None and type(self).__name__.upper() not in (
                "STORY",
                "INVESTIGATION",
                "BASELINE",
            ):
                print(
                    f"\nWarning - you are missing deprecation info for deprecated {type(self).__name__.upper()} [{self.name}]\n"
                )
                # raise ValueError(
                #     f"[{self.name}] has 'status: deprecated' set in the yml, but does not have 'deprecation_info' defined: {self.file_path}"
                # )
        elif status is None:
            # Status wasn't defined in the file
            pass
        else:
            # Status was defined but a different value, so deprecation_info should not exist
            if self.deprecation_info is not None:
                raise ValueError(
                    f"[{self.name}] has deprecation_info defined, but does not have 'status: deprecated' set in the yml at {self.file_path}"
                )

        return self

    @computed_field
    @cached_property
    @abstractmethod
    def researchSiteLink(self) -> HttpUrl:
        return HttpUrl(url="google.com")
        raise NotImplementedError(
            f"researchSiteLink has not been implemented for {self.name}"
        )

    @computed_field
    @cached_property
    def status_aware_description(self) -> str:
        """We need to be able to write out a description that includes information
        about whether or not a detection has been deprecated or not. This is important
        for providing information to the user as well as powering the deprecation
        assistant dashboad(s). Make sure this information is output correctly, if
        appropriate.
        Otherwise, if a detection is not deprecated or experimental, just return th
        unmodified description.

        Raises:
            NotImplementedError: This content type does not support status_aware_description.
            This is because the object does not define a status field

        Returns:
            str: description, which may or may not be prefixed with the deprecation/experimental message
        """
        status = getattr(self, "status", None)

        if not isinstance(status, DetectionStatus):
            raise NotImplementedError(
                f"Detection status is not implemented for [{self.name}] of type '{type(self).__name__}'"
            )
        if status == DetectionStatus.experimental:
            return EXPERIMENTAL_TEMPLATE.format(
                content_type=type(self).__name__, description=self.description
            )
        elif status == DetectionStatus.deprecated:
            return DEPRECATED_TEMPLATE.format(
                content_type=type(self).__name__, description=self.description
            )
        else:
            return self.description

    @model_serializer
    def serialize_model(self):
        return {
            "name": self.name,
            "author": self.author,
            "date": str(self.date),
            "version": self.version,
            "id": str(self.id),
            "description": self.description,
            "references": [str(url) for url in self.references or []],
        }

    def check_conf_stanza_max_length(
        self, stanza_name: str, max_stanza_length: int = CONTENTCTL_MAX_STANZA_LENGTH
    ) -> None:
        if len(stanza_name) > max_stanza_length:
            raise ValueError(
                f"conf stanza may only be {max_stanza_length} characters, "
                f"but stanza was actually {len(stanza_name)} characters: '{stanza_name}' "
            )

    @staticmethod
    def objectListToNameList(objects: list[SecurityContentObject]) -> list[str]:
        return [object.getName() for object in objects]

    # This function is overloadable by specific types if they want to redefine names, for example
    # to have the format ESCU - NAME - Rule (config.tag - self.name - Rule)
    def getName(self) -> str:
        return self.name

    @classmethod
    def contentNameToFileName(cls, content_name: str) -> str:
        return (
            content_name.replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            .replace("/", "_")
            .lower()
            + ".yml"
        )

    def ensureFileNameMatchesSearchName(self):
        file_name = self.contentNameToFileName(self.name)

        if self.file_path is not None and file_name != self.file_path.name:
            raise ValueError(
                f"The file name MUST be based off the content 'name' field:\n"
                f"\t- Expected File Name: {file_name}\n"
                f"\t- Actual File Name  : {self.file_path.name}"
            )

        return self

    @field_validator("file_path")
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
    def mapNamesToSecurityContentObjects(
        cls, v: list[str], director: Union[DirectorOutputDto, None]
    ) -> list[Self]:
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
            errors.append(
                f"Failed to find the following '{cls.__name__}': {missing_objects}"
            )
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
                f"names:\n  - {error_string}"
            )

        # Sort all objects sorted by name
        return sorted(mappedObjects, key=lambda o: o.name)

    @staticmethod
    def getDeploymentFromType(
        typeField: Union[str, None], info: ValidationInfo
    ) -> Deployment:
        if typeField is None:
            raise ValueError("'type:' field is missing from YML.")

        if info.context is None:
            raise ValueError("ValidationInfo.context unexpectedly null")

        director: Optional[DirectorOutputDto] = info.context.get("output_dto", None)
        if not director:
            raise ValueError(
                "Cannot set deployment - DirectorOutputDto not passed to Detection Constructor in context"
            )

        type_to_deployment_name_map = {
            AnalyticsType.TTP: "ESCU Default Configuration TTP",
            AnalyticsType.Hunting: "ESCU Default Configuration Hunting",
            AnalyticsType.Correlation: "ESCU Default Configuration Correlation",
            AnalyticsType.Anomaly: "ESCU Default Configuration Anomaly",
            "Baseline": "ESCU Default Configuration Baseline",
        }
        converted_type_field = type_to_deployment_name_map[typeField]

        # TODO: This is clunky, but is imported here to resolve some circular import errors
        from contentctl.objects.deployment import Deployment

        deployments = Deployment.mapNamesToSecurityContentObjects(
            [converted_type_field], director
        )
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
        names_to_find: set[str], objects_to_search: list[SecurityContentObject_Abstract]
    ) -> Tuple[list[SecurityContentObject_Abstract], set[str]]:
        raise Exception("get_objects_by_name deprecated")
        found_objects = list(
            filter(lambda obj: obj.name in names_to_find, objects_to_search)
        )
        found_names = set([obj.name for obj in found_objects])
        missing_names = names_to_find - found_names
        return found_objects, missing_names

    @staticmethod
    def create_filename_to_content_dict(
        all_objects: list[SecurityContentObject_Abstract],
    ) -> dict[str, SecurityContentObject_Abstract]:
        name_dict: dict[str, SecurityContentObject_Abstract] = dict()
        for object in all_objects:
            # If file_path is None, this function has been called on an inappropriate
            # SecurityContentObject (e.g. filter macros that are created at runtime but have no
            # actual file associated)
            if object.file_path is None:
                raise ValueError(
                    f"SecurityContentObject is missing a file_path: {object.name}"
                )
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
            raise Exception(
                f"SecurityContentObject can only be compared to each other, not to {type(other)}"
            )
        return self.name < other.name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecurityContentObject_Abstract):
            raise Exception(
                f"SecurityContentObject can only be compared to each other, not to {type(other)}"
            )

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


# class DeprecatedSecurityContentObject(SecurityContentObject_Abstract):
#     # We MUST allow extra fields here because the python definitions of the underlying
#     # objects can change. We do not want to throw pasing errors on any of these, but we will
#     # only expose fields that are defined in the SecurityContentObject definiton directly
#     model_config = ConfigDict(validate_default=True, extra="ignore")

#     @field_validator("deprecation_info")
#     def ensure_deprecation_info_is_not_none(cls, deprecation_info: Any) -> Any:
#         if deprecation_info is None:
#             raise ValueError(
#                 "DeprecatedSecurityObject does not define a valid deprecation_info object."
#             )
#         return deprecation_info


# class DeprecationInfo(BaseModel):
#     deprecation_date: datetime.date = Field(
#         ...,
#         description="On what expected date will this content be deprecated? "
#         "If an app is built after this date and attempts to write out this content, an exception will be generated.",
#     )
#     deprecation_version: Version = Field(
#         ...,
#         description="In which version of the app was this content deprecated? "
#         "If an app is built on or after this version and contains this content, an exception will be generated.",
#     )
#     reason: str = Field(
#         ...,
#         description="An explanation of why this content was deprecated.",
#         min_length=10,
#     )
#     replacement_content: list[SecurityContentObject_Abstract] = Field(
#         [],
#         description="A list of 0 to N pieces of content that replace this deprecated piece of content. "
#         "It is possible that the type(s) of the replacement content may be different than the replaced content. "
#         "For example, a detection may be replaced by a story or a macro may be replaced by a lookup.",
#     )

#     content_type: SecurityContentType = Field(
#         description="The type of this object. This must be logged separately because, "
#         "as the Python Object definitions change, we may not be able to continue "
#         "determining the type of an object based on the presence of values of its fields."
#     )

#     @computed_field
#     @cached_property
#     def migration_guide(self) -> HttpUrl:
#         """
#         A link to the research site containing a migration guide for the content

#         :returns: URL to the research site
#         :rtype: HTTPUrl
#         """

#         return HttpUrl(url=f"https://research.splunk.com/migration_guide/{self.id}")  # type: ignore

#     @staticmethod
#     def writeDeprecationCSV(
#         deprecated_content: list[DeprecatedSecurityContentObject],
#         app: CustomApp,
#         output_file: pathlib.Path,
#     ):
#         deprecation_rows: list[dict[str, str]] = []
#         for content in deprecated_content:
#             if content.deprecation_info is None:
#                 raise Exception(
#                     f"Cannot compute deprecation info for {content.name} - object has no deprecation info"
#                 )
#             content.deprecation_info.generateDeprecationLookupRow(content, app)

#         with open(output_file, "w") as deprecation_csv_file:
#             deprecation_csv_writer = DictWriter(
#                 deprecation_csv_file,
#                 fieldnames=[
#                     "Name",
#                     "ID",
#                     "Content Type",
#                     "Deprecation Date",
#                     "Deprecation Version",
#                     "Reason",
#                     "Migration Guide",
#                     "Replacement Content",
#                 ],
#             )
#             deprecation_csv_writer.writeheader()
#             deprecation_csv_writer.writerows(deprecation_rows)

#     def generateDeprecationLookupRow(
#         self, object: DeprecatedSecurityContentObject, app: CustomApp
#     ) -> dict[str, str]:
#         """
#         This function exists as a bit of a shim because pieces of content are identified in ESCU by
#         their Stanza name, which could be different than
#         """

#         # if self.content_type == SecurityContentType.detections:
#         #     content_name = Detection.static_get_conf_stanza_name(object.name, app)
#         # elif self.content_type == SecurityContentType.stories:
#         #     content_name = object.name
#         # elif self.content_type == SecurityContentType.baselines:
#         #     content_name = Baseline.static_get_conf_stanza_name(object.name, app)

#         # else:
#         #     raise Exception(
#         #         f"{self.content_type} deprecation is not supported at this time."
#         #     )

#         return {
#             "Name": content_name,
#             "ID": str(object.id),
#             "Content Type": self.content_type.name,
#             "Deprecation Date": str(self.deprecation_date),
#             "Deprecation Version": str(self.deprecation_version),
#             "Reason": "Give a unique reason in the model here",
#             "Migration Guide": str(self.migration_guide),
#             "Replacement Content": "\n".join(
#                 [str(content.researchSiteLink) for content in self.replacement_content]
#             ),
#         }
#             ),
#         }
#         }
#         }
#         }
#         }
#         }
#         }
