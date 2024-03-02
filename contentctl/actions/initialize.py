
import shutil
import os
import pathlib

from pydantic import RootModel 
from contentctl.objects.config import init
from contentctl.output.yml_writer import YmlWriter
import json




class Initialize:

    def execute(self, input_dto: init) -> None:

    
        YmlWriter.writeYmlFile(os.path.join(init.path, 'contentctl.yml'), RootModel[init](input_dto).model_dump())

        
        # This field serialization hack is required to get
        # enums declared in Pydantic Models serialized properly
        # without emitting tags that make them hard to read in yml
        
        #j = json.dumps(t.dict(),sort_keys=False)
        #obj=json.loads(j)
        #YmlWriter.writeYmlFile(os.path.join(input_dto.path, 'contentctl_test.yml'), dict(obj))


        folders = ['detections', 'stories', 'lookups', 'macros', 'baselines', 'dist', 'docs', 'reporting', 'investigations']
        for folder in folders:
            os.makedirs(os.path.join(input_dto.path, folder))

        # Working Detection
        source_path = pathlib.Path(os.path.join(os.path.dirname(__file__), '../templates/detections/'))
        dest_path = pathlib.Path(os.path.join(input_dto.path, 'detections'))
        detections_to_populate = ['anomalous_usage_of_7zip.yml']
                
        for detection_name in detections_to_populate: 
            shutil.copyfile(
                source_path/detection_name, 
                dest_path/detection_name)
        

        shutil.copytree(
            os.path.join(os.path.dirname(__file__), '../templates/deployments'), 
            os.path.join(input_dto.path, 'deployments')
        )

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

