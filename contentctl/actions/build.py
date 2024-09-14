import shutil
from dataclasses import dataclass

from contentctl.objects.enums import SecurityContentType
from contentctl.input.director import DirectorOutputDto
from contentctl.output.conf_output import ConfOutput
from contentctl.output.conf_writer import ConfWriter
from contentctl.output.api_json_output import ApiJsonOutput
from contentctl.output.data_source_writer import DataSourceWriter
from contentctl.objects.lookup import Lookup
import pathlib
import json
import datetime

from contentctl.objects.config import build

@dataclass(frozen=True)
class BuildInputDto:
    director_output_dto: DirectorOutputDto
    config:build


class Build:



    def execute(self, input_dto: BuildInputDto) -> DirectorOutputDto:
        if input_dto.config.build_app:

            updated_conf_files:set[pathlib.Path] = set()
            conf_output = ConfOutput(input_dto.config)

            # Construct a special lookup whose CSV is created at runtime and
            # written directly into the output folder. It is created with model_construct,
            # not model_validate, because the CSV does not exist yet.
            data_sources_lookup_csv_path = input_dto.config.getPackageDirectoryPath() / "lookups" / "data_sources.csv"
            DataSourceWriter.writeDataSourceCsv(input_dto.director_output_dto.data_sources, data_sources_lookup_csv_path)
            input_dto.director_output_dto.addContentToDictMappings(Lookup.model_construct(description= "A lookup file that will contain the data source objects for detections.", 
                                                                        filename=data_sources_lookup_csv_path, 
                                                                        name="data_sources"))

            updated_conf_files.update(conf_output.writeHeaders())
            updated_conf_files.update(conf_output.writeObjects(input_dto.director_output_dto.detections, SecurityContentType.detections))
            updated_conf_files.update(conf_output.writeObjects(input_dto.director_output_dto.stories, SecurityContentType.stories))
            updated_conf_files.update(conf_output.writeObjects(input_dto.director_output_dto.baselines, SecurityContentType.baselines))
            updated_conf_files.update(conf_output.writeObjects(input_dto.director_output_dto.investigations, SecurityContentType.investigations))
            updated_conf_files.update(conf_output.writeObjects(input_dto.director_output_dto.lookups, SecurityContentType.lookups))
            updated_conf_files.update(conf_output.writeObjects(input_dto.director_output_dto.macros, SecurityContentType.macros))
            updated_conf_files.update(conf_output.writeAppConf())
            
            #Ensure that the conf file we just generated/update is syntactically valid
            for conf_file in updated_conf_files:
                ConfWriter.validateConfFile(conf_file) 
                
            conf_output.packageApp()

            print(f"Build of '{input_dto.config.app.title}' APP successful to {input_dto.config.getPackageFilePath()}")
        

        if input_dto.config.build_api:    
            shutil.rmtree(input_dto.config.getAPIPath(), ignore_errors=True)
            input_dto.config.getAPIPath().mkdir(parents=True)
            api_json_output = ApiJsonOutput()
            for output_objects, output_type in [(input_dto.director_output_dto.detections, SecurityContentType.detections),
                                                (input_dto.director_output_dto.stories, SecurityContentType.stories),
                                                (input_dto.director_output_dto.baselines, SecurityContentType.baselines),
                                                (input_dto.director_output_dto.investigations, SecurityContentType.investigations),
                                                (input_dto.director_output_dto.lookups, SecurityContentType.lookups),
                                                (input_dto.director_output_dto.macros, SecurityContentType.macros),
                                                (input_dto.director_output_dto.deployments, SecurityContentType.deployments)]:
                api_json_output.writeObjects(output_objects, input_dto.config.getAPIPath(), input_dto.config.app.label, output_type )
            
           
            
            #create version file for sse api
            version_file = input_dto.config.getAPIPath()/"version.json"
            utc_time = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0,tzinfo=None).isoformat()
            version_dict = {"version":{"name":f"v{input_dto.config.app.version}","published_at": f"{utc_time}Z"  }}
            with open(version_file,"w") as version_f:
                json.dump(version_dict,version_f)
            
            print(f"Build of '{input_dto.config.app.title}' API successful to {input_dto.config.getAPIPath()}")

        return input_dto.director_output_dto