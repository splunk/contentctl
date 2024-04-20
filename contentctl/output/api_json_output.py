import os
import json
import pathlib

from contentctl.output.json_writer import JsonWriter
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import SecurityContentObject_Abstract
from typing import List,Any

class ApiJsonOutput():

 def writeObjects(self, objects: list[SecurityContentObject_Abstract], output_path: pathlib.Path, contentType: SecurityContentType = None) -> None:
        #Serialize all objects
        serialized_objects:List[dict[str,Any]] = []
        try:
            for obj in objects:
                serialized_objects.append(obj.model_dump()
        except Exception as e:
            raise Exception(f"Error serializing object with name '{obj.name}' and type '{type(obj).__name__}': '{str(e)}'")
            

        if contentType == SecurityContentType.detections:  
            JsonWriter.writeJsonObject(os.path.join(output_path, 'detections.json'), 'detections', serialized_objects )

        

        elif contentType == SecurityContentType.macros:
            for k in serialized_objects:
                #Remove arguments
                del(k['arguments'])

            JsonWriter.writeJsonObject(os.path.join(output_path, 'macros.json'), 'macros', serialized_objects )
        
        elif contentType == SecurityContentType.stories:
            obj_array = []
            for story in objects:
                story.id = str(story.id)
                obj_array.append(story.dict(exclude_none=True,
                    exclude =
                    {
                        "investigations": True
                    }
                ))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'stories.json'), 'stories', serialized_objects )

        elif contentType == SecurityContentType.baselines:
            obj_array = []
            for baseline in objects:
                baseline.id = str(baseline.id)
                obj_array.append(baseline.dict(
                    exclude =
                    {
                        "deployment": True,
                        "check_references":True,
                        "file_path":True,
                    }
                ))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'baselines.json'), 'baselines', serialized_objects )

        elif contentType == SecurityContentType.investigations:
            obj_array = []
            for investigation in objects:
                investigation.id = str(investigation.id)
                obj_array.append(investigation.dict(exclude_none=True))

            JsonWriter.writeJsonObject(os.path.join(output_path, 'response_tasks.json'), 'response_tasks', serialized_objects )
        
        elif contentType == SecurityContentType.lookups:
            obj_array = []
            for lookup in objects:

                obj_array.append(lookup.dict(exclude_none=True))


            JsonWriter.writeJsonObject(os.path.join(output_path, 'lookups.json'), 'lookups', serialized_objects )


        elif contentType == SecurityContentType.deployments:
            
            JsonWriter.writeJsonObject(os.path.join(output_path, 'deployments.json'), 'deployments', serialized_objects )
