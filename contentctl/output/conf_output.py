from dataclasses import dataclass
import os
import glob
import shutil
import sys
import tarfile
from typing import Union
from pathlib import Path
import pathlib
from splunk_appinspect.main import validate, TEST_MODE, PRECERT_MODE, JSON_DATA_FORMAT, ERROR_LOG_LEVEL
import shutil
from contentctl.output.conf_writer import ConfWriter
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.config import Config


class ConfOutput:

    input_path: str
    config: Config
    output_path: pathlib.Path
    

    def __init__(self, input_path: str, config: Config):
        self.input_path = input_path
        self.config = config
        self.output_path = pathlib.Path(self.config.build.path_root) /self.config.build.name
        self.output_path.mkdir(parents=True, exist_ok=True)
        template_splunk_app_path = os.path.join(os.path.dirname(__file__), 'templates/splunk_app')
        shutil.copytree(template_splunk_app_path, self.output_path, dirs_exist_ok=True)
        

    def writeHeaders(self) -> None:
        ConfWriter.writeConfFileHeader(self.output_path/'default/analyticstories.conf', self.config)
        ConfWriter.writeConfFileHeader(self.output_path/'default/savedsearches.conf', self.config)
        ConfWriter.writeConfFileHeader(self.output_path/'default/collections.conf', self.config)
        ConfWriter.writeConfFileHeader(self.output_path/'default/es_investigations.conf', self.config)
        ConfWriter.writeConfFileHeader(self.output_path/'default/macros.conf', self.config)
        ConfWriter.writeConfFileHeader(self.output_path/'default/transforms.conf', self.config)
        ConfWriter.writeConfFileHeader(self.output_path/'default/workflow_actions.conf', self.config)
        ConfWriter.writeConfFileHeader(self.output_path/'default/app.conf', self.config)
        


    def writeAppConf(self):
        ConfWriter.writeConfFile(self.output_path/"default"/"app.conf", "app.conf.j2", self.config, [self.config.build] )

    def writeObjects(self, objects: list, type: SecurityContentType = None) -> None:
        if type == SecurityContentType.detections:
            ConfWriter.writeConfFile(self.output_path/'default/savedsearches.conf', 
                'savedsearches_detections.j2',  
                self.config, objects)

            ConfWriter.writeConfFile(self.output_path/'default/analyticstories.conf',
                'analyticstories_detections.j2',
                self.config, objects)

            ConfWriter.writeConfFile(self.output_path/'default/macros.conf',
                'macros_detections.j2', 
                self.config, objects)
        
        elif type == SecurityContentType.stories:
            ConfWriter.writeConfFile(self.output_path/'default/analyticstories.conf', 
                'analyticstories_stories.j2',
                self.config, objects)

        elif type == SecurityContentType.baselines:
            ConfWriter.writeConfFile(self.output_path/'default/savedsearches.conf',
                'savedsearches_baselines.j2', 
                self.config, objects)

        elif type == SecurityContentType.investigations:
            ConfWriter.writeConfFile(self.output_path/'default/savedsearches.conf',
                'savedsearches_investigations.j2',
                self.config, objects)
            
            ConfWriter.writeConfFile(self.output_path/'default/analyticstories.conf',
                'analyticstories_investigations.j2', 
                self.config, objects)

            workbench_panels = []
            for investigation in objects:
                if investigation.inputs:
                    response_file_name_xml = investigation.lowercase_name + "___response_task.xml"
                    workbench_panels.append(investigation)
                    investigation.search = investigation.search.replace(">","&gt;")
                    investigation.search = investigation.search.replace("<","&lt;")
                    ConfWriter.writeConfFileHeaderEmpty(
                        self.output_path/f'default/data/ui/panels/workbench_panel_{response_file_name_xml}', 
                        self.config)
                    
                    ConfWriter.writeConfFile( self.output_path/f'default/data/ui/panels/workbench_panel_{response_file_name_xml}',
                        'panel.j2',
                        self.config,[investigation.search])

            ConfWriter.writeConfFile(self.output_path/'default/es_investigations.conf',
                'es_investigations_investigations.j2',  
                self.config, workbench_panels)

            ConfWriter.writeConfFile(self.output_path/'default/workflow_actions.conf',
                'workflow_actions.j2',  
                self.config, workbench_panels)   

        elif type == SecurityContentType.lookups:
            ConfWriter.writeConfFile(self.output_path/'default/collections.conf',
                'collections.j2', 
                self.config, objects)

            ConfWriter.writeConfFile(self.output_path/'default/transforms.conf',
                'transforms.j2', 
                self.config, objects)


            if self.input_path is None:
                raise(Exception(f"input_path is required for lookups, but received [{self.input_path}]"))

            files = glob.iglob(os.path.join(self.input_path, 'lookups', '*.csv'))
            for file in files:
                if os.path.isfile(file):
                    shutil.copy(file, os.path.join(self.output_path, 'lookups'))

        elif type == SecurityContentType.macros:
            ConfWriter.writeConfFile(self.output_path/'default/macros.conf',
                'macros.j2',
                self.config, objects)


    def packageApp(self) -> None:
        

        input_app_path = pathlib.Path(self.config.build.path_root)/f"{self.config.build.name}"
        
        readme_file = pathlib.Path("README")
        if not readme_file.is_file():
            raise Exception("The README file does not exist in this directory. Cannot build app.")
        shutil.copyfile(readme_file, input_app_path/readme_file.name)
        output_app_expected_name = pathlib.Path(self.config.build.path_root)/f"{self.config.build.name}-{self.config.build.version}.tar.gz"
        
        
        try:
            import slim
            use_slim = True
            
        except Exception as e:
            print("Failed to import Splunk Packaging Toolkit (slim).  slim requires Python<3.10.  Packaging app with tar instead")
            use_slim = False
        
        if use_slim:
            import slim
            slim.package(source=input_app_path, output_dir=pathlib.Path(self.config.build.path_root))
        else:
            with tarfile.open(output_app_expected_name, "w:gz") as app_archive:
                app_archive.add(self.output_path, arcname=os.path.basename(self.output_path)) 
                       
            
        
        if not output_app_expected_name.exists():
            raise (Exception(f"The expected output app path '{output_app_expected_name}' does not exist"))
    
    def inspectApp(self)-> None:
        
        output_app_expected_name = pathlib.Path(self.config.build.path_root)/f"{self.config.build.name}-{self.config.build.version}.tar.gz"
        name_without_version = pathlib.Path(self.config.build.path_root)/f"{self.config.build.name}.tar.gz"
        shutil.copy2(output_app_expected_name, name_without_version, follow_symlinks=False)
        
        # Note that all tags are available and described here:
        # https://dev.splunk.com/enterprise/reference/appinspect/appinspecttagreference/ 
        included_tags = ["appapproval", 
                         "cloud", 
                         "packaging_standards", 
                         "private_app", 
                         "private_victoria", 
                         "savedsearches", 
                         "security", 
                         "service", 
                         "splunk_9_0", 
                         "splunk_appinspect"]
        included_tags_string =','.join(included_tags)
        excluded_tags = []

        excluded_tags_string = ','.join(excluded_tags)
        try:
            validate([str(name_without_version)], PRECERT_MODE, included_tags_string, excluded_tags_string)
        except SystemExit as e:
            if e.code == 0:
                print("AppInspect passed!")
            else:
                if sys.version.startswith('3.11') or sys.version.startswith('3.12'):
                    raise Exception("At this time, AppInspect may fail on valid apps under Python>=3.11 with " 
                                    "the error 'global flags not at the start of the expression at position 1'. "  
                                    "If you encounter this error, please run AppInspect on a version of Python "
                                    "<3.11.  This issue is currently tracked. Please review the appinspect "
                                    "report output above for errors.")
                else: 
                    raise Exception("AppInspect Failure - Please review the appinspect report output above for errors.")        