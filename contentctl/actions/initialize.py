
import shutil
import os
import pathlib

from pydantic import RootModel 
from contentctl.objects.config import test
from contentctl.output.yml_writer import YmlWriter


class Initialize:

    def execute(self, config: test) -> None:
        # construct a test object from the init object
        # This way we can easily populate a yml with ALL the important
        # fields for validating, building, and testing your app. 
        
        YmlWriter.writeYmlFile(str(config.path/'contentctl.yml'), config.model_dump()) 

        #Create the following empty directories:
        for emptyDir in ['lookups', 'baselines', 'docs', 'reporting', 'investigations']:
            #Throw an error if this directory already exists
            (config.path/emptyDir).mkdir(exist_ok=False)
        

        #copy the contents of all template directories
        for templateDir, targetDir in [
            ('../templates/app_template/', 'app_template'),
            ('../templates/deployments/', 'deployments'),
            ('../templates/detections/', 'detections'),
            ('../templates/data_sources/', 'data_sources'),
            ('../templates/macros/','macros'),
            ('../templates/stories/', 'stories'),
        ]:
            source_directory = pathlib.Path(os.path.dirname(__file__))/templateDir
            target_directory = config.path/targetDir
            #Throw an exception if the target exists
            shutil.copytree(source_directory, target_directory, dirs_exist_ok=False)
        
        #Create the config file as well
        shutil.copyfile(pathlib.Path(os.path.dirname(__file__))/'../templates/README','README')


        print(f"The app '{config.app.title}' has been initialized. "
              "Please run 'contentctl new --type {detection,story}' to create new content")

