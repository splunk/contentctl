from dataclasses import dataclass
import os
import glob
import shutil
import sys
import tarfile
from typing import Union
from pathlib import Path
import pathlib
import time
import timeit
import datetime
import shutil
import json
from contentctl.output.conf_writer import ConfWriter
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.config import build
from requests import Session, post, get
from requests.auth import HTTPBasicAuth

class ConfOutput:
    config: build    


    def __init__(self, config: build):
        self.config = config

        #Create the build directory if it does not exist
        config.getPackageDirectoryPath().parent.mkdir(parents=True, exist_ok=True)
        
        #Remove the app path, if it exists
        shutil.rmtree(config.getPackageDirectoryPath(), ignore_errors=True)
        
        #Copy all the template files into the app
        shutil.copytree(config.getAppTemplatePath(), config.getPackageDirectoryPath())
        

    def writeHeaders(self) -> set[pathlib.Path]:
        written_files:set[pathlib.Path] = set()
        for output_app_path in ['default/analyticstories.conf', 
                                'default/savedsearches.conf', 
                                'default/collections.conf', 
                                'default/es_investigations.conf', 
                                'default/macros.conf', 
                                'default/transforms.conf', 
                                'default/workflow_actions.conf', 
                                'default/app.conf',
                                'default/content-version.conf']:
            written_files.add(ConfWriter.writeConfFileHeader(pathlib.Path(output_app_path),self.config))
            
        return written_files

        
        #The contents of app.manifest are not a conf file, but json.
        #DO NOT write a header for this file type, simply create the file
        with open(self.config.getPackageDirectoryPath() / pathlib.Path('app.manifest'), 'w') as f:
            pass
            

    def writeAppConf(self)->set[pathlib.Path]:
        written_files:set[pathlib.Path] = set()
        for output_app_path, template_name in [ ("default/app.conf", "app.conf.j2"),
                                                ("default/content-version.conf", "content-version.j2")]:
            written_files.add(ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                    template_name,
                                    self.config,
                                    [self.config.app]))
        
        written_files.add(ConfWriter.writeManifestFile(pathlib.Path("app.manifest"),
                                              "app.manifest.j2",
                                              self.config,
                                              [self.config.app]))
        return written_files

        
    def writeObjects(self, objects: list, type: SecurityContentType = None) -> set[pathlib.Path]:
        written_files:set[pathlib.Path] = set()
        if type == SecurityContentType.detections:
            for output_app_path, template_name in [ ('default/savedsearches.conf', 'savedsearches_detections.j2'),
                                                    ('default/analyticstories.conf', 'analyticstories_detections.j2')]:
                written_files.add(ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                                           template_name, self.config, objects))
        
        elif type == SecurityContentType.stories:
            written_files.add(ConfWriter.writeConfFile(pathlib.Path('default/analyticstories.conf'), 
                                    'analyticstories_stories.j2',
                                    self.config, objects))

        elif type == SecurityContentType.baselines:
            written_files.add(ConfWriter.writeConfFile(pathlib.Path('default/savedsearches.conf'),
                                                      'savedsearches_baselines.j2', 
                                                       self.config, objects))

        elif type == SecurityContentType.investigations:
            for output_app_path, template_name in [ ('default/savedsearches.conf', 'savedsearches_investigations.j2'),
                                                    ('default/analyticstories.conf', 'analyticstories_investigations.j2')]:
                ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                         template_name,
                                         self.config,
                                         objects)
                
            workbench_panels = []
            for investigation in objects:
                if investigation.inputs:
                    response_file_name_xml = investigation.lowercase_name + "___response_task.xml"
                    workbench_panels.append(investigation)
                    investigation.search = investigation.search.replace(">","&gt;")
                    investigation.search = investigation.search.replace("<","&lt;")
                    
                    
                    ConfWriter.writeXmlFileHeader(pathlib.Path(f'default/data/ui/panels/workbench_panel_{response_file_name_xml}'), 
                                                        self.config)
                    
                    ConfWriter.writeXmlFile(    pathlib.Path(f'default/data/ui/panels/workbench_panel_{response_file_name_xml}'),
                                                'panel.j2',
                                                self.config,[investigation.search])

            for output_app_path, template_name in [ ('default/es_investigations.conf', 'es_investigations_investigations.j2'),
                                                    ('default/workflow_actions.conf', 'workflow_actions.j2')]:
                written_files.add( ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                                         template_name,
                                                        self.config,
                                                        workbench_panels))

        elif type == SecurityContentType.lookups:
            for output_app_path, template_name in [ ('default/collections.conf', 'collections.j2'),
                                                    ('default/transforms.conf', 'transforms.j2')]:
                written_files.add(ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                            template_name,
                                            self.config,
                                            objects))
            
        
            #we want to copy all *.mlmodel files as well, not just csvs
            files = list(glob.iglob(str(self.config.path/ 'lookups/*.csv'))) + list(glob.iglob(str(self.config.path / 'lookups/*.mlmodel')))
            lookup_folder = self.config.getPackageDirectoryPath()/"lookups"
            
            # Make the new folder for the lookups 
            # This folder almost certainly already exists because mitre_enrichment.csv has been writtent here from the app template.
            lookup_folder.mkdir(exist_ok=True)

            #Copy each lookup into the folder
            for lookup_name in files:
                lookup_path = pathlib.Path(lookup_name)
                if lookup_path.is_file():
                    shutil.copy(lookup_path, lookup_folder/lookup_path.name)
                else:
                    raise(Exception(f"Error copying lookup/mlmodel file.  Path {lookup_path} does not exist or is not a file."))

        elif type == SecurityContentType.macros:
            written_files.add(ConfWriter.writeConfFile(pathlib.Path('default/macros.conf'),
                                    'macros.j2',
                                    self.config, objects))
        
        return written_files
            



    
    def packageAppTar(self) -> None:
    
        with tarfile.open(self.config.getPackageFilePath(include_version=True), "w:gz") as app_archive:
            app_archive.add(self.config.getPackageDirectoryPath(), arcname=self.config.getPackageDirectoryPath().name) 
                       
        shutil.copy2(self.config.getPackageFilePath(include_version=True), 
                     self.config.getPackageFilePath(include_version=False), 
                     follow_symlinks=False)
    
    def packageAppSlim(self) -> None:
        

        # input_app_path = pathlib.Path(self.config.build.path_root)/f"{self.config.build.name}"
        
        # readme_file = pathlib.Path("README")
        # if not readme_file.is_file():
        #     raise Exception("The README file does not exist in this directory. Cannot build app.")
        # shutil.copyfile(readme_file, input_app_path/readme_file.name)
        
        
        try:
            import slim
            from slim.utils import SlimLogger
            import logging
            #In order to avoid significant output, only emit FATAL log messages
            SlimLogger.set_level(logging.ERROR)
            try:
                slim.package(source=self.config.getPackageDirectoryPath(), output_dir=pathlib.Path(self.config.getBuildDir()))
            except SystemExit as e:
                raise Exception(f"Error building package with slim: {str(e)}")
        
        
        except Exception as e:
            print("Failed to import Splunk Packaging Toolkit (slim).  slim requires Python<3.10.  "
                  "Packaging app with tar instead. This should still work, but appinspect may catch "
                  "errors that otherwise would have been flagged by slim.")
            raise Exception(f"slim (splunk packaging toolkit) not installed: {str(e)}")
            
        
        
    def packageApp(self, method=packageAppTar)->None:
        return method(self)

        
        
    def getElapsedTime(self, startTime:float)->datetime.timedelta:
        return datetime.timedelta(seconds=round(timeit.default_timer() - startTime))
        
    