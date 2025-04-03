import sys
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

from pydantic import TypeAdapter, ValidationError

from contentctl.enrichments.attack_enrichment import AttackEnrichment
from contentctl.enrichments.cve_enrichment import CveEnrichment
from contentctl.helper.utils import Utils
from contentctl.input.yml_reader import YmlReader
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import (
    DeprecationDocumentationFile,
)
from contentctl.objects.atomic import AtomicEnrichment
from contentctl.objects.baseline import Baseline
from contentctl.objects.config import validate
from contentctl.objects.dashboard import Dashboard
from contentctl.objects.data_source import DataSource
from contentctl.objects.deployment import Deployment
from contentctl.objects.deprecated_security_content_object import (
    DeprecatedSecurityContentObject,
)
from contentctl.objects.detection import Detection
from contentctl.objects.enums import ContentStatus
from contentctl.objects.investigation import Investigation
from contentctl.objects.lookup import (
    CSVLookup,
    KVStoreLookup,
    Lookup,
    LookupAdapter,
    MlModel,
)
from contentctl.objects.macro import Macro
from contentctl.objects.playbook import Playbook
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.story import Story


@dataclass
class DirectorOutputDto:
    # Atomic Tests are first because parsing them
    # is far quicker than attack_enrichment
    atomic_enrichment: AtomicEnrichment
    attack_enrichment: AttackEnrichment
    cve_enrichment: CveEnrichment
    detections: list[Detection]
    stories: list[Story]
    baselines: list[Baseline]
    investigations: list[Investigation]
    playbooks: list[Playbook]
    macros: list[Macro]
    lookups: list[Lookup]
    deployments: list[Deployment]
    dashboards: list[Dashboard]
    deprecated: list[DeprecatedSecurityContentObject]
    data_sources: list[DataSource]
    deprecation_documentation: DeprecationDocumentationFile | None = None
    name_to_content_map: dict[str, SecurityContentObject] = field(default_factory=dict)
    uuid_to_content_map: dict[UUID, SecurityContentObject] = field(default_factory=dict)

    def addContentToDictMappings(self, content: SecurityContentObject):
        content_name = content.name

        if content_name in self.name_to_content_map:
            raise ValueError(
                f"Duplicate name '{content_name}' with paths:\n"
                f" - {content.file_path}\n"
                f" - {self.name_to_content_map[content_name].file_path}"
            )

        if content.id in self.uuid_to_content_map:
            raise ValueError(
                f"Duplicate id '{content.id}' with paths:\n"
                f" - {content.file_path}\n"
                f" - {self.uuid_to_content_map[content.id].file_path}"
            )

        if isinstance(content, Lookup):
            self.lookups.append(content)
        elif isinstance(content, Macro):
            self.macros.append(content)
        elif isinstance(content, Deployment):
            self.deployments.append(content)
        elif isinstance(content, Playbook):
            self.playbooks.append(content)
        elif isinstance(content, Baseline):
            self.baselines.append(content)
        elif isinstance(content, Investigation):
            self.investigations.append(content)
        elif isinstance(content, Story):
            self.stories.append(content)
        elif isinstance(content, Detection):
            self.detections.append(content)
        elif isinstance(content, Dashboard):
            self.dashboards.append(content)
        elif isinstance(content, DataSource):
            self.data_sources.append(content)
        elif isinstance(content, DeprecatedSecurityContentObject):
            self.deprecated.append(content)
        else:
            raise Exception(f"Unknown security content type: {type(content)}")

        self.name_to_content_map[content_name] = content
        self.uuid_to_content_map[content.id] = content


class Director:
    input_dto: validate
    output_dto: DirectorOutputDto

    def __init__(self, output_dto: DirectorOutputDto) -> None:
        self.output_dto = output_dto

    def execute(self, input_dto: validate) -> None:
        self.input_dto = input_dto
        self.createSecurityContent(Deployment)
        self.createSecurityContent(LookupAdapter)
        self.createSecurityContent(Macro)
        self.createSecurityContent(Story)
        self.createSecurityContent(Baseline)
        # self.createSecurityContent(Investigation)
        self.createSecurityContent(DataSource)
        self.createSecurityContent(Playbook)
        self.createSecurityContent(Detection)
        self.createSecurityContent(Dashboard)
        self.createSecurityContent(DeprecatedSecurityContentObject)
        self.validateDeprecation()

    def validateDeprecation(self):
        data = YmlReader.load_file(
            self.input_dto.path / "removed" / "deprecation_mapping.YML"
        )
        from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import (
            DeprecationDocumentationFile,
        )

        mapping = DeprecationDocumentationFile.model_validate(
            data, context={"output_dto": self.output_dto, "config": self.input_dto}
        )

        all_deprecated_content = list(
            filter(
                lambda content: getattr(content, "status", None)
                in [ContentStatus.deprecated, ContentStatus.removed],
                self.output_dto.name_to_content_map.values(),
            )
        )
        print(
            f"\n\nThe length of all deprecated or removed content is: {len(all_deprecated_content)}\n\n"
        )
        for content in all_deprecated_content:
            if getattr(content, "deprecation_info", None) is None:
                print(
                    f"[{type(content).__name__} - {content.name}] - Missing deprecation_info"
                )
        self.output_dto.deprecation_documentation = mapping

    def createSecurityContent(
        self,
        contentType: type[SecurityContentObject]
        | TypeAdapter[CSVLookup | KVStoreLookup | MlModel],
    ) -> None:
        files = Utils.get_all_yml_files_from_directory(
            self.input_dto.path / contentType.containing_folder()  # type: ignore
        )

        # convert this generator to a list so that we can
        # calculate progress as we iterate over the files
        security_content_files = [f for f in files]

        validation_errors: list[tuple[Path, ValueError]] = []

        already_ran = False
        progress_percent = 0
        context: dict[str, validate | DirectorOutputDto] = {
            "output_dto": self.output_dto,
            "config": self.input_dto,
        }
        contentCartegoryName: str = contentType.__name__.upper()  # type: ignore

        for index, file in enumerate(security_content_files):
            progress_percent = ((index + 1) / len(security_content_files)) * 100
            try:
                type_string = contentType.__name__.upper()  # type: ignore
                modelDict = YmlReader.load_file(file)

                if isinstance(contentType, type(SecurityContentObject)):
                    content: SecurityContentObject = contentType.model_validate(
                        modelDict, context=context
                    )
                elif contentType == LookupAdapter:
                    content: SecurityContentObject = (  # type: ignore
                        contentType.validate_python(modelDict, context=context)  # type:ignore
                    )
                    if not isinstance(content, SecurityContentObject):
                        raise Exception(
                            f"Expected lookup to be a SecurityContentObject (CSVLookup, KVStoreLookup, or MLModel), but it was actually: {type(content)}"  # type: ignore
                        )
                else:
                    raise Exception(f"Unknown contentType in Director: {contentType}")

                self.output_dto.addContentToDictMappings(content)

                if (
                    sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()
                ) or not already_ran:
                    already_ran = True
                    print(
                        f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...",
                        end="",
                        flush=True,
                    )

            except (ValidationError, ValueError) as e:
                relative_path = file.absolute().relative_to(
                    self.input_dto.path.absolute()
                )
                validation_errors.append((relative_path, e))

        print(
            f"\r{f'{contentCartegoryName} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...",
            end="",
            flush=True,
        )
        print("Done!")

        if len(validation_errors) > 0:
            errors_string = "\n\n".join(
                [
                    f"File: {e_tuple[0]}\nError: {str(e_tuple[1])}"
                    for e_tuple in validation_errors
                ]
            )
            # print(f"The following {len(validation_errors)} error(s) were found during validation:\n\n{errors_string}\n\nVALIDATION FAILED")
            # We quit after validation a single type/group of content because it can cause significant cascading errors in subsequent
            # types of content (since they may import or otherwise use it)
            raise Exception(
                f"The following {len(validation_errors)} error(s) were found during validation:\n\n{errors_string}\n\nVALIDATION FAILED"
            )
