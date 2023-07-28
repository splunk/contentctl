from dataclasses import dataclass
import os
import glob
import shutil
import sys
import tarfile
from typing import Union
from pathlib import Path
import pathlib

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
            print("Failed to import Splunk Packaging Toolkit (slim).  slim requires Python<3.10.  "
                  "Packaging app with tar instead. This should still work, but appinspect may catch "
                  "errors that otherwise would have been flagged by slim.")
            use_slim = False
        
        if use_slim:
            import slim
            from slim.utils import SlimLogger
            import logging
            #In order to avoid significant output, only emit FATAL log messages
            SlimLogger.set_level(logging.ERROR)
            try:
                slim.package(source=input_app_path, output_dir=pathlib.Path(self.config.build.path_root))
            except SystemExit as e:
                raise Exception(f"Error building package with slim: {str(e)}")
        else:
            with tarfile.open(output_app_expected_name, "w:gz") as app_archive:
                app_archive.add(self.output_path, arcname=os.path.basename(self.output_path)) 
                       
            
        
        if not output_app_expected_name.exists():
            raise (Exception(f"The expected output app path '{output_app_expected_name}' does not exist"))
    
    def inspectApp(self)-> None:
        
        output_app_expected_name = pathlib.Path(self.config.build.path_root)/f"{self.config.build.name}-{self.config.build.version}.tar.gz"
        name_without_version = pathlib.Path(self.config.build.path_root)/f"{self.config.build.name}.tar.gz"
        shutil.copy2(output_app_expected_name, name_without_version, follow_symlinks=False)
        
        try:
            from splunk_appinspect.main import (
                validate, MODE_OPTION, APP_PACKAGE_ARGUMENT, OUTPUT_FILE_OPTION, 
                LOG_FILE_OPTION, INCLUDED_TAGS_OPTION, EXCLUDED_TAGS_OPTION, 
                PRECERT_MODE, TEST_MODE)
        except Exception as e:
            print("******WARNING******")
            if sys.version_info.major == 3 and sys.version_info.minor == 9:
                print("The package splunk-appinspect was not installed due to a current issue with the library on Python3.10+.  "
                      "Please use the following commands to set up a virtualenvironment in a different folder so you may run appinspect manually:"
                      f"\n\tpython3.9 -m venv .venv; source .venv/bin/activate; python3 -m pip install splunk-appinspect; splunk-appinspect inspect {name_without_version} --mode precert")    
                
            else:
                print("splunk-appinspect is only compatable with Python3.9 at this time.  Please see the following open issue here: https://github.com/splunk/contentctl/issues/28")
            print("******WARNING******")
            return

        # Note that all tags are available and described here:
        # https://dev.splunk.com/enterprise/reference/appinspect/appinspecttagreference/ 
        # By default, precert mode will run ALL checks.  Explicitly included or excluding tags will 
        # change this behavior. To give the most thorough inspection, we leave these empty so that
        # ALL checks are run
        included_tags = []
        excluded_tags = []

        appinspect_output = pathlib.Path(self.config.build.path_root)/"appinspect_results.json"
        appinspect_logging = pathlib.Path(self.config.build.path_root)/"appinspect_logging.log"
        try:
            arguments_list = [(APP_PACKAGE_ARGUMENT, str(name_without_version))]
            options_list = []
            options_list += [MODE_OPTION, TEST_MODE]
            options_list += [OUTPUT_FILE_OPTION, str(appinspect_output)]
            options_list += [LOG_FILE_OPTION, str(appinspect_logging)]
            
            #If there are any tags defined, then include them here
            for opt in included_tags:
                options_list += [INCLUDED_TAGS_OPTION, opt]
            for opt in excluded_tags:
                options_list += [EXCLUDED_TAGS_OPTION, opt]

            cmdline = options_list + [arg[1] for arg in arguments_list]        
            validate(cmdline)
    
        except SystemExit as e:
            if e.code == 0:
                # The sys.exit called inside of appinspect validate closes stdin.  We need to
                # reopen it.
                sys.stdin = open("/dev/stdin","r")
                print(f"AppInspect passed! Please check [ {appinspect_output} , {appinspect_logging} ] for verbose information.")
            else:
                if sys.version.startswith('3.11') or sys.version.startswith('3.12'):
                    raise Exception("At this time, AppInspect may fail on valid apps under Python>=3.11 with " 
                                    "the error 'global flags not at the start of the expression at position 1'. "  
                                    "If you encounter this error, please run AppInspect on a version of Python "
                                    "<3.11.  This issue is currently tracked. Please review the appinspect "
                                    "report output above for errors.")
                else: 
                    raise Exception("AppInspect Failure - Please review the appinspect report output above for errors.")        
        finally:
                # appinspect outputs the log in json format, but does not format it to be easier
                # to read (it is all in one line). Read back that file and write it so it
                # is easier to understand
                try:
                    with open(appinspect_output, "r+") as logfile:
                        import json
                        j = json.load(logfile)
                        #Seek back to the beginning of the file. We don't need to clear
                        #it sice we will always write AT LEAST the same number of characters
                        #back as we read
                        logfile.seek(0)
                        json.dump(j, logfile, indent=3, )
                except Exception as e:
                    print(f"Failed to format {appinspect_output}: {str(e)}")