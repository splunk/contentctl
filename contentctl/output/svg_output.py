import os
import pathlib

from contentctl.objects.enums import SecurityContentType
from contentctl.output.jinja_writer import JinjaWriter
from contentctl.objects.config import Config

class SvgOutput():

    def writeObjects(self, objects: list, path: str, type: SecurityContentType = None) -> None:
        
        detections_tmp = objects
        detection_without_test = 0    

        output_path = pathlib.Path(path)

        detections = []
        obj = dict()

        for detection in detections_tmp:
            if not detection.status == "deprecated":
                detections.append(detection)

                if not detection.tests and not detection.experimental:
                    detection_without_test = detection_without_test + 1


        obj['count'] = len(detections) 
        obj['coverage'] = (obj['count'] - detection_without_test)/obj['count']
        obj['coverage'] = "{:.0%}".format(obj['coverage'])

        JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'detection_count.svg'), obj)
        JinjaWriter.writeObject('detection_coverage.j2', os.path.join(output_path, 'detection_coverage.svg'), obj)

