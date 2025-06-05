from __future__ import annotations

from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    from contentctl.objects.config import CustomApp
    from contentctl.objects.deployment import Deployment
import abc
import datetime
import pathlib
import pprint
import uuid
from abc import abstractmethod
from collections import Counter
from difflib import get_close_matches
from functools import cached_property
from typing import List, Optional, Tuple, Union

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
from rich import console, table
from semantic_version import Version

from contentctl.objects.constants import (
    CONTENTCTL_MAX_STANZA_LENGTH,
    DEPRECATED_TEMPLATE,
    EXPERIMENTAL_TEMPLATE,
)
from contentctl.objects.enums import (
    CONTENT_STATUS_THAT_REQUIRES_DEPRECATION_INFO,
    AnalyticsType,
    ContentStatus,
)


class DeprecationInfo(BaseModel):
    contentType: type[SecurityContentObject_Abstract]
    removed_in_version: str = Field(
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

    @model_validator(mode="after")
    def noDeprecatedOrRemovedReplacementContent(self) -> Self:
        from contentctl.objects.detection import Detection
        from contentctl.objects.story import Story

        bad_mapping_types = [
            content
            for content in self.replacement_content
            if not (isinstance(content, Story) or isinstance(content, Detection))
        ]
        if len(bad_mapping_types) > 0:
            names_only = [
                f"{content.name} - {type(content).__name__}"
                for content in bad_mapping_types
            ]
            raise ValueError(
                f"Replacement content MUST have type {Story.__name__} or {Detection.__name__}: {names_only}"
            )

        deprecated_replacement_content = [
            content
            for content in self.replacement_content
            if content.status in CONTENT_STATUS_THAT_REQUIRES_DEPRECATION_INFO
        ]

        if len(deprecated_replacement_content) > 0:
            names_only = [
                f"{content.name} - {content.status}"
                for content in deprecated_replacement_content
            ]
            raise ValueError(
                f"Replacement content cannot have status deprecated or removed {names_only}"
            )

        return self

    class DeprecationException(Exception):
        app: CustomApp
        content_name: str
        content_type_from_content: str
        content_type_from_deprecation_mapping: str
        content_status_from_yml: str
        removed_in_version: str
        UNDEFINED_VALUE: str = "N/A"

        def __init__(
            self,
            app: CustomApp,
            content_name: str = UNDEFINED_VALUE,
            content_type_from_content: str = UNDEFINED_VALUE,
            content_type_from_deprecation_mapping: str = UNDEFINED_VALUE,
            content_status_from_yml: str = UNDEFINED_VALUE,
            removed_in_version: str = UNDEFINED_VALUE,
        ):
            self.app = app
            self.content_name = content_name
            self.content_type_from_content = content_type_from_content
            self.content_type_from_deprecation_mapping = (
                content_type_from_deprecation_mapping
            )
            self.content_status_from_yml = content_status_from_yml
            self.removed_in_version = removed_in_version

        @abstractmethod
        def message(self) -> str:
            raise NotImplementedError(
                "Base Deprecation Exception does not implement the message function."
            )

        def generateTableRow(
            self,
        ) -> tuple[str, str, str, str, str, str, str]:
            return (
                self.content_name,
                self.content_type_from_content,
                self.content_type_from_deprecation_mapping,
                self.content_status_from_yml,
                self.removed_in_version,
                self.app.version,
                self.message(),
            )

        @staticmethod
        def renderExceptionsAsTable(
            exceptions: list[DeprecationInfo.DeprecationException],
        ):
            t = table.Table(title="Content Deprecation and Removal Errors")
            t.add_column("Content Name", justify="left", style="cyan", no_wrap=True)
            t.add_column("Type (YML)", justify="left", style="yellow", no_wrap=True)
            t.add_column("Type (Mapping)", justify="left", style="yellow", no_wrap=True)
            t.add_column("Status (YML)", justify="left", style="magenta", no_wrap=True)
            t.add_column(
                "Remove In",
                justify="left",
                style="magenta",
                no_wrap=True,
            )
            t.add_column(
                "App Version",
                justify="left",
                style="magenta",
                no_wrap=True,
            )
            t.add_column("Error Message", justify="left", style="red", no_wrap=False)

            for e in exceptions:
                t.add_row(*e.generateTableRow())

            console.Console().print(t)

    class DeprecationInfoMissing(DeprecationException):
        def __init__(self, app: CustomApp, obj: SecurityContentObject_Abstract):
            super().__init__(
                app=app,
                content_name=obj.name,
                content_type_from_content=type(obj).__name__,
                content_status_from_yml=obj.status,
            )

        def message(self) -> str:
            return "Missing entry in deprecation_mapping.YML"

    class NoContentForDeprecationInfo(DeprecationException):
        def __init__(self, app: CustomApp, deprecation_info: DeprecationInfoInFile):
            super().__init__(
                app=app,
                content_name=deprecation_info.content,
                content_type_from_deprecation_mapping=deprecation_info.content_type.__name__,
                removed_in_version=deprecation_info.removed_in_version,
            )

        def message(self) -> str:
            return "Exists in deprecation_mapping.yml, but it does not match a piece of content."

    class DeprecationStatusMismatch(DeprecationException):
        def __init__(
            self,
            app: CustomApp,
            obj: SecurityContentObject_Abstract,
            deprecation_info: DeprecationInfoInFile,
        ):
            super().__init__(
                app=app,
                content_name=obj.name,
                content_type_from_content=type(obj).__name__,
                content_type_from_deprecation_mapping=deprecation_info.content_type.__name__,
                content_status_from_yml=obj.status,
                removed_in_version=deprecation_info.removed_in_version,
            )

        def message(self) -> str:
            if Version(self.app.version) >= Version(self.removed_in_version):
                val = ContentStatus.removed
            else:
                val = ContentStatus.deprecated
            return f"Based on 'Remove In' and 'App Version', Content Status should be {val}"

    class DeprecationTypeMismatch(DeprecationException):
        def __init__(
            self,
            app: CustomApp,
            obj: SecurityContentObject_Abstract,
            deprecation_info: DeprecationInfoInFile,
        ):
            super().__init__(
                app=app,
                content_name=obj.name,
                content_type_from_content=type(obj).__name__,
                content_type_from_deprecation_mapping=deprecation_info.content_type.__name__,
                content_status_from_yml=obj.status,
                removed_in_version=deprecation_info.removed_in_version,
            )

        def message(self) -> str:
            return "The type of the content yml and in the deprecation_mapping.YML do not match."

    class DeprecationInfoDoubleMapped(DeprecationException):
        def __init__(
            self,
            app: CustomApp,
            obj: SecurityContentObject_Abstract,
            deprecation_info: DeprecationInfoInFile,
        ):
            super().__init__(
                app=app,
                content_name=obj.name,
                content_type_from_content=type(obj).__name__,
                content_type_from_deprecation_mapping=deprecation_info.content_type.__name__,
                content_status_from_yml=obj.status,
                removed_in_version=deprecation_info.removed_in_version,
            )

        def message(self) -> str:
            return "Any entry in the deprecation_mapping.YML file mapped to two pieces of content."

    @classmethod
    def constructFromFileInfoAndDirector(
        cls, info: DeprecationInfoInFile, director: DirectorOutputDto
    ) -> DeprecationInfo:
        replacement_content = (
            SecurityContentObject_Abstract.mapNamesToSecurityContentObjects(
                info.replacement_content, director
            )
        )
        return cls(
            contentType=info.content_type,
            removed_in_version=info.removed_in_version,
            reason=info.reason,
            replacement_content=replacement_content,
        )


class DeprecationInfoInFile(BaseModel):
    content: str
    mapped: bool = False
    content_type: type = Field(
        description="This value is inferred from the section of the file that the content occurs in."
    )
    removed_in_version: str = Field(
        ...,
        description="In which version of the app was this content deprecated? "
        "If an app is built on or after this version and contains this content, an exception will be generated.",
    )

    reason: str = Field(
        ...,
        description="An explanation of why this content was deprecated.",
        min_length=6,
    )
    replacement_content: list[str] = Field(
        [],
        description="A list of 0 to N pieces of content that replace this deprecated piece of content. "
        "It is possible that the type(s) of the replacement content may be different than the replaced content. "
        "For example, a detection may be replaced by a story or a macro may be replaced by a lookup.",
    )


class DeprecationDocumentationFile(BaseModel):
    # The follow are presently supported
    baselines: list[DeprecationInfoInFile] = []
    detections: list[DeprecationInfoInFile] = []
    investigations: list[DeprecationInfoInFile] = []
    stories: list[DeprecationInfoInFile] = []

    # These types may be supported in the future
    dashboards: list[DeprecationInfoInFile] = []
    data_sources: list[DeprecationInfoInFile] = []
    deployments: list[DeprecationInfoInFile] = []
    lookups: list[DeprecationInfoInFile] = []
    macros: list[DeprecationInfoInFile] = []

    def __add__(self, o: DeprecationDocumentationFile) -> DeprecationDocumentationFile:
        return DeprecationDocumentationFile(
            baselines=self.baselines + o.baselines,
            detections=self.detections + o.detections,
            investigations=self.investigations + o.investigations,
            stories=self.stories + o.stories,
            dashboards=self.dashboards + o.dashboards,
            data_sources=self.data_sources + o.data_sources,
            deployments=self.deployments + o.deployments,
            macros=self.macros + o.macros,
        )

    @computed_field
    @property
    def all_content(self) -> list[DeprecationInfoInFile]:
        return (
            self.baselines
            + self.detections
            + self.investigations
            + self.stories
            + self.dashboards
            + self.data_sources
            + self.deployments
            + self.macros
        )

    @computed_field
    @property
    def mapping(self) -> dict[str, DeprecationInfoInFile]:
        mapping: dict[str, DeprecationInfoInFile] = {}
        for content in self.all_content:
            mapping[content.content] = content
        return mapping

    @model_validator(mode="after")
    def ensureUniqueNames(self) -> Self:
        all_names: list[str] = [n.content for n in self.all_content]
        duplicate_names: set[str] = set()
        for name in all_names:
            if all_names.count(name) > 1:
                duplicate_names.add(name)
        if len(duplicate_names) > 0:
            raise ValueError(
                f"The following content names were defined more than once in deprection_mapping.YML:{duplicate_names}"
            )
        return self

    def mapAllContent(self, director: DirectorOutputDto, app: CustomApp) -> None:
        mapping_exceptions: list[DeprecationInfo.DeprecationException] = []

        # Check that every piece of content which should have a mapping
        # in the file does
        for content in director.name_to_content_map.values():
            try:
                content.deprecation_info = self.getMappedContent(content, director, app)
            except DeprecationInfo.DeprecationException as e:
                mapping_exceptions.append(e)

        # Check that every entry in the file actually maps to a piece of content
        unmapped_deprecations = [d for d in self.mapping.values() if not d.mapped]
        for unmapped_deprecation in unmapped_deprecations:
            mapping_exceptions.append(
                DeprecationInfo.NoContentForDeprecationInfo(app, unmapped_deprecation)
            )

        if len(mapping_exceptions):
            DeprecationInfo.DeprecationException.renderExceptionsAsTable(
                mapping_exceptions
            )
            raise Exception(
                f"{len(mapping_exceptions)} error processing deprecation_mapping.YML"
            )

    def getMappedContent(
        self,
        obj: SecurityContentObject_Abstract,
        director: DirectorOutputDto,
        app: CustomApp,
    ) -> DeprecationInfo | None:
        deprecation_info: DeprecationInfoInFile | None = self.mapping.get(
            obj.name, None
        )

        obj.checkDeprecationInfo(app, deprecation_info)
        if deprecation_info is None:
            return

        return DeprecationInfo.constructFromFileInfoAndDirector(
            deprecation_info, director
        )

    @field_validator(
        "detections",
        "baselines",
        "investigations",
        "stories",
        mode="before",
    )
    @classmethod
    def setTypeSupportedContent(
        cls, v: list[dict[str, Any] | DeprecationInfoInFile], info: ValidationInfo
    ) -> list[dict[str, Any] | DeprecationInfoInFile]:
        """
        This function is important because we need to ensure that the heading a piece of
        content is under in the Deprecation File matches the actual type of that content.
        For non-removed content, this is a bit easier since the content itself carries a
        type.  However, it is more difficult for DeprecatedSecurityContent_Object since
        that no longer has a meaningful type, every piece of removed content has the same
        typing. In that case, the heading in the deprecation mapping file is used to
        determine proper type information for that content.
        """
        for entry in v:
            if isinstance(entry, DeprecationInfoInFile):
                # This is already a fully loaded/parsed Object and we are probably
                # getting here by adding two of them together.  No need to do the
                # enrichment as the content_type has already been set.
                continue

            if info.field_name == "detections":
                from contentctl.objects.detection import Detection

                entry["content_type"] = Detection
            elif info.field_name == "baselines":
                from contentctl.objects.baseline import Baseline

                entry["content_type"] = Baseline
            elif info.field_name == "stories":
                from contentctl.objects.story import Story

                entry["content_type"] = Story
            elif info.field_name == "investigations":
                from contentctl.objects.investigation import Investigation

                entry["content_type"] = Investigation
            else:
                raise Exception(
                    f"Trying to map list of unsupported content types '{info.field_name}' in the Mapping YML"
                )
        return v

    @field_validator(
        "dashboards",
        "data_sources",
        "deployments",
        "lookups",
        "macros",
        mode="before",
    )
    @classmethod
    def setTypeUnsupportedContent(
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
    status: ContentStatus = Field(
        description="All SecurityContentObjects must have a status.  "
        "Further refinements to status are included in each specific object, "
        "since not every object supports all possible statuses.  "
        "This is done via a slightly complex regex scheme due to "
        "limitations in Type Checking."
    )

    def checkDeprecationInfo(
        self, app: CustomApp, deprecation_info: DeprecationInfoInFile | None
    ):
        if deprecation_info is None:
            if self.status not in CONTENT_STATUS_THAT_REQUIRES_DEPRECATION_INFO:
                return
            else:
                raise DeprecationInfo.DeprecationInfoMissing(app, self)

        if deprecation_info.mapped:
            # This content was already mapped - we cannot use it again and should give an exception
            raise DeprecationInfo.DeprecationInfoDoubleMapped(
                app, self, deprecation_info
            )

        # Once an entry is mapped ot the file, we cannot map to it again
        # Even if we generate an exception later in this function, we still want
        # to mark the deprecation info as mapped because we did successfully handle it
        deprecation_info.mapped = True

        # Make sure that the type in the deprecation info matches the type of
        # the object
        if type(self) is not deprecation_info.content_type:
            from contentctl.objects.removed_security_content_object import (
                RemovedSecurityContentObject,
            )

            if type(self) is not RemovedSecurityContentObject:
                raise DeprecationInfo.DeprecationTypeMismatch(
                    app, self, deprecation_info
                )

        # This means we have deprecation info
        if self.status not in CONTENT_STATUS_THAT_REQUIRES_DEPRECATION_INFO:
            # However this piece of content should not have the info
            raise DeprecationInfo.DeprecationStatusMismatch(app, self, deprecation_info)

        # Content should be removed if the app version is greater than or equal to
        # when we say the content should be removed
        removed_in = Version(deprecation_info.removed_in_version)
        current_version = Version(app.version)

        if current_version >= removed_in:
            # Content should have status removed
            if self.status is not ContentStatus.removed:
                raise DeprecationInfo.DeprecationStatusMismatch(
                    app, self, deprecation_info
                )
        else:
            if self.status is not ContentStatus.deprecated:
                raise DeprecationInfo.DeprecationStatusMismatch(
                    app, self, deprecation_info
                )

    @classmethod
    def NarrowStatusTemplate(
        cls, status: ContentStatus, allowed_types: list[ContentStatus]
    ) -> ContentStatus:
        if status not in allowed_types:
            raise ValueError(
                f"The status '{status}' is not allowed. Only {allowed_types} are supported status for this object."
            )
        return status

    @field_validator("status", mode="after")
    @classmethod
    def NarrowStatus(cls, status: ContentStatus) -> ContentStatus:
        raise NotImplementedError(
            "Narrow Status must be implemented for each SecurityContentObject"
        )

    @classmethod
    @abstractmethod
    def containing_folder(cls) -> pathlib.Path:
        raise NotImplementedError(
            f"Containing folder has not been implemented for {cls.__name__}"
        )

    def model_post_init(self, __context: Any) -> None:
        self.ensureFileNameMatchesSearchName()

    @computed_field
    @cached_property
    @abstractmethod
    def researchSiteLink(self) -> HttpUrl:
        raise NotImplementedError(
            f"researchSiteLink has not been implemented for [{type(self).__name__} - {self.name}]"
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

        if not isinstance(status, ContentStatus):
            raise NotImplementedError(
                f"Detection status is not implemented for [{self.name}] of type '{type(self).__name__}'"
            )
        if status == ContentStatus.experimental:
            return EXPERIMENTAL_TEMPLATE.format(
                content_type=type(self).__name__, description=self.description
            )
        elif status == ContentStatus.deprecated:
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

    @classmethod
    def static_get_conf_stanza_name(cls, name: str, app: CustomApp) -> str:
        raise NotImplementedError(
            "{cls.__name__} does not have an implementation for static_get_conf_stanza_name"
        )

    def get_conf_stanza_name(self, app: CustomApp) -> str:
        stanza_name = self.static_get_conf_stanza_name(self.name, app)
        self.check_conf_stanza_max_length(stanza_name)
        return stanza_name

    @staticmethod
    def objectListToNameList(
        objects: list[SecurityContentObject_Abstract],
    ) -> list[str]:
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
        if director is None:
            raise Exception(
                "Direction was 'None' when passed to "
                "'mapNamesToSecurityContentObjects'. This is "
                "an error in the contentctl codebase which must be resolved."
            )

        # Catch all for finding duplicates in mapped content
        if (
            len(duplicates := [name for name, count in Counter(v).items() if count > 1])
            > 0
        ):
            raise ValueError(
                f"Duplicate {cls.__name__} ({duplicates}) found in list: {v}."
            )

        mappedObjects: list[Self] = []
        mistyped_objects: list[SecurityContentObject_Abstract] = []
        missing_objects: list[str] = []
        for object_name in v:
            found_object = director.name_to_content_map.get(object_name, None)
            if not found_object:
                missing_objects.append(object_name)
            elif not isinstance(found_object, cls):
                mistyped_objects.append(found_object)
            else:
                mappedObjects.append(found_object)

        errors: list[str] = []
        for missing_object in missing_objects:
            if missing_object.endswith("_filter"):
                # Most filter macros are defined as empty at runtime, so we do not
                # want to make any suggestions.  It is time consuming and not helpful
                # to make these suggestions, so we just skip them in this check.
                continue
            matches = get_close_matches(
                missing_object,
                director.name_to_content_map.keys(),
                n=3,
            )
            if matches == []:
                matches = ["NO SUGGESTIONS"]

            matches_string = ", ".join(matches)
            errors.append(
                f"Unable to find: {missing_object}\n       Suggestions: {matches_string}"
            )

        for mistyped_object in mistyped_objects:
            matches = get_close_matches(
                mistyped_object.name, director.name_to_content_map.keys(), n=3
            )

            errors.append(
                f"'{mistyped_object.name}' expected to have type '{cls.__name__}', but actually "
                f"had type '{type(mistyped_object).__name__}'"
            )

        if len(errors) > 0:
            error_string = "\n\n  - ".join(errors)
            raise ValueError(
                f"Found {len(errors)} issues when resolving references to '{cls.__name__}' objects:\n"
                f"  - {error_string}"
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
