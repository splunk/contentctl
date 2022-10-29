from dataclasses import dataclass
import os
import glob
import shutil
from typing import Union

from splunk_contentctl.output.conf_writer import ConfWriter
from splunk_contentctl.objects.enums import SecurityContentType


class ConfOutput:
    input_path: str
    app_name: str

    def __init__(self, input_path: str):
        self.input_path = input_path
        self.app_name = 'ESCU'

    def writeHeaders(self, output_folder: str) -> None:
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/analyticstories.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/savedsearches.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/collections.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/es_investigations.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/macros.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/transforms.conf'))
        ConfWriter.writeConfFileHeader(os.path.join(output_folder, 'default/workflow_actions.conf'))


    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:
        if type == SecurityContentType.detections:
            ConfWriter.writeConfFile('savedsearches_detections.j2', 
            os.path.join(output_path, 'default/savedsearches.conf'), 
            objects,self.app_name)

            ConfWriter.writeConfFile('analyticstories_detections.j2',
                os.path.join(output_path, 'default/analyticstories.conf'), 
                objects,self.app_name)

            ConfWriter.writeConfFile('macros_detections.j2',
                os.path.join(output_path, 'default/macros.conf'), 
                objects,self.app_name)
        
        elif type == SecurityContentType.stories:
            ConfWriter.writeConfFile('analyticstories_stories.j2',
                os.path.join(output_path, 'default/analyticstories.conf'), 
                objects,self.app_name)

        elif type == SecurityContentType.baselines:
            ConfWriter.writeConfFile('savedsearches_baselines.j2', 
                os.path.join(output_path, 'default/savedsearches.conf'), 
                objects,self.app_name)

        elif type == SecurityContentType.investigations:
            ConfWriter.writeConfFile('savedsearches_investigations.j2', 
                os.path.join(output_path, 'default/savedsearches.conf'), 
                objects,self.app_name)
            
            ConfWriter.writeConfFile('analyticstories_investigations.j2', 
                os.path.join(output_path, 'default/analyticstories.conf'), 
                objects,self.app_name)

            workbench_panels = []
            for investigation in objects:
                if investigation.inputs:
                    response_file_name_xml = investigation.lowercase_name + "___response_task.xml"
                    workbench_panels.append(investigation)
                    investigation.search = investigation.search.replace(">","&gt;")
                    investigation.search = investigation.search.replace("<","&lt;")
                    ConfWriter.writeConfFileHeaderEmpty(os.path.join(output_path, 
                        'default/data/ui/panels/', str("workbench_panel_" + response_file_name_xml)))
                    ConfWriter.writeConfFile('panel.j2', 
                        os.path.join(output_path, 
                        'default/data/ui/panels/', str("workbench_panel_" + response_file_name_xml)),
                        [investigation.search],self.app_name)

            ConfWriter.writeConfFile('es_investigations_investigations.j2', 
                os.path.join(output_path, 'default/es_investigations.conf'), 
                workbench_panels,self.app_name)

            ConfWriter.writeConfFile('workflow_actions.j2', 
                os.path.join(output_path, 'default/workflow_actions.conf'), 
                workbench_panels,self.app_name)   

        elif type == SecurityContentType.lookups:
            ConfWriter.writeConfFile('collections.j2', 
                os.path.join(output_path, 'default/collections.conf'), 
                objects,self.app_name)

            ConfWriter.writeConfFile('transforms.j2', 
                os.path.join(output_path, 'default/transforms.conf'), 
                objects,self.app_name)


            if self.input_path is None:
                raise(Exception(f"input_path is required for lookups, but received [{self.input_path}]"))

            files = glob.iglob(os.path.join(self.input_path, 'lookups', '*.csv'))
            for file in files:
                if os.path.isfile(file):
                    shutil.copy(file, os.path.join(output_path, 'lookups'))

        elif type == SecurityContentType.macros:
            ConfWriter.writeConfFile('macros.j2', 
                os.path.join(output_path, 'default/macros.conf'), 
                objects,self.app_name)

