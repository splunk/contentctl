from dataclasses import dataclass
import os
import glob
import shutil
import tarfile
from typing import Union
from pathlib import Path

from splunk_contentctl.output.conf_writer import ConfWriter
from splunk_contentctl.objects.enums import SecurityContentType
from splunk_contentctl.objects.config import Config


class ConfOutput:
    input_path: str
    output_path: str
    app_name: str

    def __init__(self, input_path: str, config: Config):
        self.input_path = input_path
        self.app_name = config.build.splunk_app.prefix
        self.output_path = os.path.join(input_path, config.build.splunk_app.path)
        Path(self.output_path).mkdir(parents=True, exist_ok=True)
        template_splunk_app_path = os.path.join(os.path.dirname(__file__), '../templates/splunk_app')
        shutil.copytree(template_splunk_app_path, self.output_path, dirs_exist_ok=True)


    def writeHeaders(self) -> None:
        ConfWriter.writeConfFileHeader(os.path.join(self.output_path, 'default/analyticstories.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(self.output_path, 'default/savedsearches.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(self.output_path, 'default/collections.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(self.output_path, 'default/es_investigations.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(self.output_path, 'default/macros.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(self.output_path, 'default/transforms.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(self.output_path, 'default/workflow_actions.conf'))


    def writeObjects(self, objects: list, type: SecurityContentType = None) -> None:
        if type == SecurityContentType.detections:
            ConfWriter.writeConfFile('savedsearches_detections.j2', 
            os.path.join(self.output_path, 'default/savedsearches.conf'), 
            objects,self.app_name)

            ConfWriter.writeConfFile('analyticstories_detections.j2',
                os.path.join(self.output_path, 'default/analyticstories.conf'), 
                objects,self.app_name)

            ConfWriter.writeConfFile('macros_detections.j2',
                os.path.join(self.output_path, 'default/macros.conf'), 
                objects,self.app_name)
        
        elif type == SecurityContentType.stories:
            ConfWriter.writeConfFile('analyticstories_stories.j2',
                os.path.join(self.output_path, 'default/analyticstories.conf'), 
                objects,self.app_name)

        elif type == SecurityContentType.baselines:
            ConfWriter.writeConfFile('savedsearches_baselines.j2', 
                os.path.join(self.output_path, 'default/savedsearches.conf'), 
                objects,self.app_name)

        elif type == SecurityContentType.investigations:
            ConfWriter.writeConfFile('savedsearches_investigations.j2', 
                os.path.join(self.output_path, 'default/savedsearches.conf'), 
                objects,self.app_name)
            
            ConfWriter.writeConfFile('analyticstories_investigations.j2', 
                os.path.join(self.output_path, 'default/analyticstories.conf'), 
                objects,self.app_name)

            workbench_panels = []
            for investigation in objects:
                if investigation.inputs:
                    response_file_name_xml = investigation.lowercase_name + "___response_task.xml"
                    workbench_panels.append(investigation)
                    investigation.search = investigation.search.replace(">","&gt;")
                    investigation.search = investigation.search.replace("<","&lt;")
                    ConfWriter.writeConfFileHeaderEmpty(os.path.join(self.output_path, 
                        'default/data/ui/panels/', str("workbench_panel_" + response_file_name_xml)))
                    ConfWriter.writeConfFile('panel.j2', 
                        os.path.join(self.output_path, 
                        'default/data/ui/panels/', str("workbench_panel_" + response_file_name_xml)),
                        [investigation.search],self.app_name)

            ConfWriter.writeConfFile('es_investigations_investigations.j2', 
                os.path.join(self.output_path, 'default/es_investigations.conf'), 
                workbench_panels,self.app_name)

            ConfWriter.writeConfFile('workflow_actions.j2', 
                os.path.join(self.output_path, 'default/workflow_actions.conf'), 
                workbench_panels,self.app_name)   

        elif type == SecurityContentType.lookups:
            ConfWriter.writeConfFile('collections.j2', 
                os.path.join(self.output_path, 'default/collections.conf'), 
                objects,self.app_name)

            ConfWriter.writeConfFile('transforms.j2', 
                os.path.join(self.output_path, 'default/transforms.conf'), 
                objects,self.app_name)


            if self.input_path is None:
                raise(Exception(f"input_path is required for lookups, but received [{self.input_path}]"))

            files = glob.iglob(os.path.join(self.input_path, 'lookups', '*.csv'))
            for file in files:
                if os.path.isfile(file):
                    shutil.copy(file, os.path.join(self.output_path, 'lookups'))

        elif type == SecurityContentType.macros:
            ConfWriter.writeConfFile('macros.j2', 
                os.path.join(self.output_path, 'default/macros.conf'), 
                objects,self.app_name)


    def packageApp(self) -> None:
        name = self.output_path + ".tar.gz"

        with tarfile.open(name, "w:gz") as app_archive:
            app_archive.add(self.output_path, arcname=os.path.basename(self.output_path))
