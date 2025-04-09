import datetime
import json
import pathlib
import shutil
import uuid
from dataclasses import dataclass

from contentctl.input.director import DirectorOutputDto
from contentctl.objects.config import build
from contentctl.objects.lookup import Lookup_Type, RuntimeCSV
from contentctl.output.api_json_output import ApiJsonOutput
from contentctl.output.conf_output import ConfOutput
from contentctl.output.conf_writer import ConfWriter
from contentctl.output.data_source_writer import DataSourceWriter


@dataclass(frozen=True)
class BuildInputDto:
    director_output_dto: DirectorOutputDto
    config: build


class Build:
    def execute(self, input_dto: BuildInputDto) -> DirectorOutputDto:
        if input_dto.config.build_app:
            updated_conf_files: set[pathlib.Path] = set()
            conf_output = ConfOutput(input_dto.config)
            datasource_lookup = RuntimeCSV(
                name="data_sources",
                id=uuid.UUID("b45c1403-6e09-47b0-824f-cf6e44f15ac8"),
                version=1,
                author=input_dto.config.app.author_name,
                date=datetime.date.today(),
                description="A lookup file that contains the data source objects for detections.",
                lookup_type=Lookup_Type.csv,
                contents=DataSourceWriter.generateDatasourceCSVContents(
                    input_dto.director_output_dto.data_sources
                ),
            )
            input_dto.director_output_dto.addContentToDictMappings(datasource_lookup)

            deprecation_lookup = RuntimeCSV(
                name="deprecation_info",
                id=uuid.UUID("99262bf2-9606-4b52-b377-c96713527b35"),
                version=1,
                author=input_dto.config.app.author_name,
                date=datetime.date.today(),
                description="A lookup file that contains information about content that has been deprecated or removed from the app.",
                lookup_type=Lookup_Type.csv,
                contents=DataSourceWriter.generateDeprecationCSVContents(
                    input_dto.director_output_dto, input_dto.config.app
                ),
            )
            input_dto.director_output_dto.addContentToDictMappings(deprecation_lookup)

            updated_conf_files.update(conf_output.writeHeaders())
            updated_conf_files.update(
                conf_output.writeLookups(input_dto.director_output_dto.lookups)
            )
            updated_conf_files.update(
                conf_output.writeDetections(input_dto.director_output_dto.detections)
            )
            updated_conf_files.update(
                conf_output.writeStories(input_dto.director_output_dto.stories)
            )
            updated_conf_files.update(
                conf_output.writeBaselines(input_dto.director_output_dto.baselines)
            )
            updated_conf_files.update(
                conf_output.writeInvestigations(
                    input_dto.director_output_dto.investigations
                )
            )
            updated_conf_files.update(
                conf_output.writeMacros(input_dto.director_output_dto.macros)
            )
            updated_conf_files.update(
                conf_output.writeDashboards(input_dto.director_output_dto.dashboards)
            )
            updated_conf_files.update(conf_output.writeMiscellaneousAppFiles())

            # Ensure that the conf file we just generated/update is syntactically valid
            for conf_file in updated_conf_files:
                ConfWriter.validateConfFile(conf_file)

            conf_output.packageApp()

            print(
                f"Build of '{input_dto.config.app.title}' APP successful to {input_dto.config.getPackageFilePath()}"
            )

        if input_dto.config.build_api:
            shutil.rmtree(input_dto.config.getAPIPath(), ignore_errors=True)
            input_dto.config.getAPIPath().mkdir(parents=True)
            api_json_output = ApiJsonOutput(
                input_dto.config.getAPIPath(), input_dto.config.app.label
            )
            api_json_output.writeDetections(input_dto.director_output_dto.detections)
            api_json_output.writeStories(input_dto.director_output_dto.stories)
            api_json_output.writeBaselines(input_dto.director_output_dto.baselines)
            api_json_output.writeInvestigations(
                input_dto.director_output_dto.investigations
            )
            api_json_output.writeLookups(input_dto.director_output_dto.lookups)
            api_json_output.writeMacros(input_dto.director_output_dto.macros)
            api_json_output.writeDeployments(input_dto.director_output_dto.deployments)

            # create version file for sse api
            version_file = input_dto.config.getAPIPath() / "version.json"
            utc_time = (
                datetime.datetime.now(datetime.timezone.utc)
                .replace(microsecond=0, tzinfo=None)
                .isoformat()
            )
            version_dict = {
                "version": {
                    "name": f"v{input_dto.config.app.version}",
                    "published_at": f"{utc_time}Z",
                }
            }
            with open(version_file, "w") as version_f:
                json.dump(version_dict, version_f)

            print(
                f"Build of '{input_dto.config.app.title}' API successful to {input_dto.config.getAPIPath()}"
            )

        return input_dto.director_output_dto
