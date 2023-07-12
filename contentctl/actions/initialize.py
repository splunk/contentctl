
import shutil
import os
import pathlib
from dataclasses import dataclass
from contentctl.objects.config import Config, TestConfig, PASSWORD
from contentctl.output.yml_writer import YmlWriter

@dataclass(frozen=True)
class InitializeInputDto:
    path: pathlib.Path
    demo: bool = False


class Initialize:

    def execute(self, input_dto: InitializeInputDto) -> None:

        c = Config()
        
        t = TestConfig.construct(splunk_app_username="admin",
                                 splunk_app_password= PASSWORD) #Disable validation for default object

        config_as_dict = c.dict()
        config_as_dict.pop("test")
        YmlWriter.writeYmlFile(os.path.join(input_dto.path, 'contentctl.yml'), config_as_dict)

        
        # This field serialization hack is required to get
        # enums declared in Pydantic Models serialized properly
        # without emitting tags that make them hard to read in yml
        import json
        j = json.dumps(t.dict(),sort_keys=False)
        obj=json.loads(j)
        YmlWriter.writeYmlFile(os.path.join(input_dto.path, 'contentctl_test.yml'), dict(obj))


        folders = ['detections', 'stories', 'lookups', 'macros', 'baselines', 'dist', 'docs', 'reporting']
        for folder in folders:
            os.makedirs(os.path.join(input_dto.path, folder))

        # Working Detection
        source_path = pathlib.Path(os.path.join(os.path.dirname(__file__), '../templates/detections/'))
        dest_path = pathlib.Path(os.path.join(input_dto.path, 'detections'))
        detections_to_populate = ['anomalous_usage_of_7zip.yml']
        if input_dto.demo:
            detections_to_populate += ['anomalous_usage_of_7zip_validation_fail.yml', 
                                      'anomalous_usage_of_7zip_test_fail.yml']     
                
        for detection_name in detections_to_populate: 
            shutil.copyfile(
                source_path/detection_name, 
                dest_path/detection_name)
        

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/stories/cobalt_strike.yml'), 
            os.path.join(input_dto.path, 'stories', 'cobalt_strike.yml')
        )

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/macros/security_content_ctime.yml'), 
            os.path.join(input_dto.path, 'macros', 'security_content_ctime.yml')
        )

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/macros/security_content_summariesonly.yml'), 
            os.path.join(input_dto.path, 'macros', 'security_content_summariesonly.yml')
        )

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/README'), 
            os.path.join(input_dto.path, 'README')
        )

        print('The following folders were created: {0} under {1}.\nContent pack has been initialized, please run `new` to create new content.'.format(folders, input_dto.path))

