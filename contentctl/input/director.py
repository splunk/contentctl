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
from contentctl.objects.config import CustomApp, validate
from contentctl.objects.dashboard import Dashboard
from contentctl.objects.data_source import DataSource
from contentctl.objects.deployment import Deployment
from contentctl.objects.detection import Detection
from contentctl.objects.investigation import Investigation
from contentctl.objects.lookup import (
    CSVLookup,
    KVStoreLookup,
    Lookup,
    Lookup_Type,
    LookupAdapter,
    MlModel,
    RuntimeCSV,
)
from contentctl.objects.macro import Macro
from contentctl.objects.playbook import Playbook
from contentctl.objects.removed_security_content_object import (
    RemovedSecurityContentObject,
)
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.story import Story
from contentctl.output.runtime_csv_writer import RuntimeCsvWriter


@dataclass
class DirectorOutputDto:
    # Atomic Tests are first because parsing them
    # is far quicker than attack_enrichment
    atomic_enrichment: AtomicEnrichment
    attack_enrichment: AttackEnrichment
    cve_enrichment: CveEnrichment
    detections: list[Detection] = field(default_factory=list)
    stories: list[Story] = field(default_factory=list)
    baselines: list[Baseline] = field(default_factory=list)
    investigations: list[Investigation] = field(default_factory=list)
    playbooks: list[Playbook] = field(default_factory=list)
    macros: list[Macro] = field(default_factory=list)
    lookups: list[Lookup] = field(default_factory=list)
    deployments: list[Deployment] = field(default_factory=list)
    dashboards: list[Dashboard] = field(default_factory=list)
    deprecated: list[RemovedSecurityContentObject] = field(default_factory=list)
    data_sources: list[DataSource] = field(default_factory=list)
    deprecation_documentation: DeprecationDocumentationFile = field(
        default_factory=DeprecationDocumentationFile
    )
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
        elif isinstance(content, RemovedSecurityContentObject):
            self.deprecated.append(content)
        else:
            raise Exception(f"Unknown security content type: {type(content)}")

        self.name_to_content_map[content_name] = content
        self.uuid_to_content_map[content.id] = content


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"
    MAGENTA = "\033[35m"
    BRIGHT_MAGENTA = "\033[95m"

    # Add fallback symbols for Windows
    CHECK_MARK = "✓" if sys.platform != "win32" else "*"
    WARNING = "⚠️" if sys.platform != "win32" else "!"
    ERROR = "❌" if sys.platform != "win32" else "X"
    ARROW = "🎯" if sys.platform != "win32" else ">"
    TOOLS = "🛠️" if sys.platform != "win32" else "#"
    DOCS = "📚" if sys.platform != "win32" else "?"
    BULB = "💡" if sys.platform != "win32" else "i"
    SEARCH = "🔍" if sys.platform != "win32" else "@"
    SPARKLE = "✨" if sys.platform != "win32" else "*"
    ZAP = "⚡" if sys.platform != "win32" else "!"


class ValidationFailedError(Exception):
    """Custom exception for validation failures that already have formatted output."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class Director:
    input_dto: validate
    output_dto: DirectorOutputDto

    def __init__(self, output_dto: DirectorOutputDto) -> None:
        self.output_dto = output_dto

    def execute(self, input_dto: validate) -> None:
        self.input_dto = input_dto

        for content in [
            Deployment,
            LookupAdapter,
            Macro,
            Story,
            Baseline,
            DataSource,
            Playbook,
            Detection,
            Dashboard,
            RemovedSecurityContentObject,
        ]:
            self.createSecurityContent(content)

        self.loadDeprecationInfo(input_dto.app)
        self.buildRuntimeCsvs()

    def buildRuntimeCsvs(self):
        self.buildDataSourceCsv()
        self.buildDeprecationRemovalCsv()

    def buildDeprecationRemovalCsv(self):
        if self.input_dto.enforce_deprecation_mapping_requirement is False:
            # Do not build the CSV, it would be wasteful to include it if it
            # is not even used
            return
        deprecation_lookup = RuntimeCSV(
            name="deprecation_info",
            id=UUID("99262bf2-9606-4b52-b377-c96713527b35"),
            version=1,
            author=self.input_dto.app.author_name,
            description="A lookup file that contains information about content that has been deprecated or removed from the app.",
            lookup_type=Lookup_Type.csv,
            contents=RuntimeCsvWriter.generateDeprecationCSVContent(
                self.output_dto, self.input_dto.app
            ),
        )
        self.output_dto.addContentToDictMappings(deprecation_lookup)

    def buildDataSourceCsv(self):
        datasource_lookup = RuntimeCSV(
            name="data_sources",
            id=UUID("b45c1403-6e09-47b0-824f-cf6e44f15ac8"),
            version=1,
            author=self.input_dto.app.author_name,
            description="A lookup file that contains the data source objects for detections.",
            lookup_type=Lookup_Type.csv,
            contents=RuntimeCsvWriter.generateDatasourceCSVContent(
                self.output_dto.data_sources
            ),
        )
        self.output_dto.addContentToDictMappings(datasource_lookup)

    def loadDeprecationInfo(self, app: CustomApp):
        mapping_file_paths = list(
            (self.input_dto.path / "removed").glob("deprecation_mapping*.YML")
        )

        if self.input_dto.enforce_deprecation_mapping_requirement is False:
            # If we are not required to enforce deprecation mapping, then do nothing at all (even if the files exist)
            if len(mapping_file_paths) > 0:
                file_paths = "\n - " + "\n - ".join(
                    str(name) for name in mapping_file_paths
                )
                print(
                    "The following deprecation_mapping*.YML files were found, but will not be parsed because "
                    f"[enforce_deprecation_mapping_requirement = {self.input_dto.enforce_deprecation_mapping_requirement}]:",
                    file_paths,
                )
            # Otherwise, no need to output extra information
            return

        # If there are no mapping files, that's okay.  We will other throw exceptions later on if
        # there are 1 or more detections marked as deprecated or removed.
        for mapping_file_path in mapping_file_paths:
            print(f"Parsing mapping file {mapping_file_path.name}")
            data = YmlReader.load_file(mapping_file_path)
            mapping = DeprecationDocumentationFile.model_validate(data)
            self.output_dto.deprecation_documentation += mapping

        self.output_dto.deprecation_documentation.mapAllContent(self.output_dto, app)

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

        if len(validation_errors) > 0:
            if sys.platform == "win32":
                sys.stdout.reconfigure(encoding="utf-8")

            print("\n")  # Clean separation
            print(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}╔{'═' * 60}╗{Colors.END}")
            print(
                f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}║{Colors.BLUE}{f'{Colors.SEARCH} Content Validation Summary':^59}{Colors.BRIGHT_MAGENTA}║{Colors.END}"
            )
            print(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}╚{'═' * 60}╝{Colors.END}\n")

            print(
                f"{Colors.BOLD}{Colors.GREEN}{Colors.SPARKLE} Validation Completed{Colors.END} – Issues detected in {Colors.RED}{Colors.BOLD}{len(validation_errors)}{Colors.END} files.\n"
            )

            for index, entry in enumerate(validation_errors, 1):
                file_path, error = entry
                width = max(70, len(str(file_path)) + 15)

                # File header with numbered emoji
                number_emoji = f"{index}️⃣"
                print(f"{Colors.YELLOW}┏{'━' * width}┓{Colors.END}")
                print(
                    f"{Colors.YELLOW}┃{Colors.BOLD} {number_emoji} File: {Colors.CYAN}{file_path}{Colors.END}{' ' * (width - len(str(file_path)) - 9)}{Colors.YELLOW}┃{Colors.END}"
                )
                print(f"{Colors.YELLOW}┗{'━' * width}┛{Colors.END}")

                print(
                    f"   {Colors.RED}{Colors.BOLD}{Colors.ZAP} Validation Issues:{Colors.END}"
                )

                if isinstance(error, ValidationError):
                    for err in error.errors():
                        error_msg = err.get("msg", "")
                        if "https://errors.pydantic.dev" in error_msg:
                            # Unfortunately, this is a catch-all for untyped errors. We will still need to emit this
                            # This is harder to read, but the other option is suppressing it which we cannot do as
                            # it makes troubleshooting extremelt difficult
                            print(
                                f"      {Colors.RED}{Colors.ERROR} {error_msg}{Colors.END}"
                            )

                        # Clean error categorization
                        elif "Field required" in error_msg:
                            print(
                                f"      {Colors.YELLOW}{Colors.WARNING} Field Required: {err.get('loc', [''])[0]}{Colors.END}"
                            )
                        elif "Input should be" in error_msg:
                            print(
                                f"      {Colors.MAGENTA}{Colors.ARROW} Invalid Value for {err.get('loc', [''])[0]}{Colors.END}"
                            )
                            if err.get("ctx", {}).get("expected", None) is not None:
                                print(
                                    f"        Valid options: {err.get('ctx', {}).get('expected', None)}"
                                )
                        elif "Extra inputs" in error_msg:
                            print(
                                f"      {Colors.BLUE}{Colors.ERROR} Unexpected Field: {err.get('loc', [''])[0]}{Colors.END}"
                            )
                        elif "Failed to find" in error_msg:
                            print(
                                f"      {Colors.RED}{Colors.SEARCH} Missing Reference: {error_msg}{Colors.END}"
                            )
                        else:
                            print(
                                f"      {Colors.RED}{Colors.ERROR} {error_msg}{Colors.END}"
                            )
                else:
                    print(f"      {Colors.RED}{Colors.ERROR} {str(error)}{Colors.END}")
                print("")

            # Clean footer with next steps
            max_width = max(60, max(len(str(e[0])) + 15 for e in validation_errors))
            print(f"{Colors.BOLD}{Colors.CYAN}╔{'═' * max_width}╗{Colors.END}")
            print(
                f"{Colors.BOLD}{Colors.CYAN}║{Colors.BLUE}{Colors.ARROW + ' Next Steps':^{max_width - 1}}{Colors.CYAN}║{Colors.END}"
            )
            print(f"{Colors.BOLD}{Colors.CYAN}╚{'═' * max_width}╝{Colors.END}\n")

            print(
                f"{Colors.GREEN}{Colors.TOOLS} Fix the validation issues in the listed files{Colors.END}"
            )
            print(
                f"{Colors.YELLOW}{Colors.DOCS} Check the documentation: {Colors.UNDERLINE}https://github.com/splunk/contentctl{Colors.END}"
            )
            print(
                f"{Colors.BLUE}{Colors.BULB} Use --verbose for detailed error information{Colors.END}\n"
            )

            raise ValidationFailedError(
                f"Validation failed with {len(validation_errors)} error(s)"
            )

        # Success case
        print(
            f"\r{f'{contentCartegoryName} Progress'.rjust(23)}: [{progress_percent:3.0f}%]... {Colors.GREEN}{Colors.CHECK_MARK} Done!{Colors.END}"
        )
