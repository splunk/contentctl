import os
import json


from contentctl.output.json_writer import JsonWriter
from contentctl.objects.enums import SecurityContentType

# Maximum Lambda Request Response Limit is 6MB
# https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
# Note that if you are not using AWS Lambda, this file size may be increased.
AWS_LAMBDA_LIMIT = 1024 * 1024 * 6 - 1


class ApiJsonOutput:
    def writeObjects(
        self, objects: list, output_path: str, type: SecurityContentType = None
    ) -> None:
        if type == SecurityContentType.detections:
            obj_array = []
            for detection in objects:
                detection.id = str(detection.id)
                obj_array.append(
                    detection.dict(
                        exclude_none=True,
                        exclude={
                            "deprecated": True,
                            "experimental": True,
                            "annotations": True,
                            "risk": True,
                            "playbooks": True,
                            "baselines": True,
                            "mappings": True,
                            "test": True,
                            "deployment": True,
                            "type": True,
                            "status": True,
                            "data_source": True,
                            "tests": True,
                            "cve_enrichment": True,
                            "file_path": True,
                            "tags": {
                                "file_path": True,
                                "required_fields": True,
                                "confidence": True,
                                "impact": True,
                                "product": True,
                                "cve": True,
                            },
                        },
                    )
                )

            for detection in obj_array:
                # Loop through each macro in the detection
                for macro in detection["macros"]:
                    # Remove the 'file_path' key if it exists
                    macro.pop("file_path", None)

            JsonWriter.writeJsonObject(
                os.path.join(output_path, "detections.json"), {"detections": obj_array}
            )

            ### Code to be added to contentctl to ship filter macros to macros.json

            obj_array = []
            for detection in objects:
                detection_dict = detection.dict()
                if "macros" in detection_dict:
                    for macro in detection_dict["macros"]:
                        obj_array.append(macro)

            uniques: set[str] = set()
            for obj in obj_array:
                if obj.get("arguments", None) != None:
                    uniques.add(json.dumps(obj, sort_keys=True))
                else:
                    obj.pop("arguments")
                    uniques.add(json.dumps(obj, sort_keys=True))

            obj_array = []
            for item in uniques:
                obj_array.append(json.loads(item))

            for obj in obj_array:
                if "file_path" in obj:
                    del obj["file_path"]

            JsonWriter.writeJsonObject(
                os.path.join(output_path, "macros.json"), {"macros": obj_array}
            )

        elif type == SecurityContentType.stories:
            obj_array = []
            for story in objects:
                story.id = str(story.id)
                obj_array.append(
                    story.dict(
                        exclude_none=True,
                        exclude={"investigations": True, "file_path": True},
                    )
                )

            JsonWriter.writeJsonObject(
                os.path.join(output_path, "stories.json"), {"stories": obj_array}
            )

        elif type == SecurityContentType.baselines:
            obj_array = []
            for baseline in objects:
                baseline.id = str(baseline.id)
                obj_array.append(
                    baseline.dict(
                        exclude={
                            "deployment": True,
                            "check_references": True,
                            "file_path": True,
                        }
                    )
                )

            JsonWriter.writeJsonObject(
                os.path.join(output_path, "baselines.json"), {"baselines": obj_array}
            )

        elif type == SecurityContentType.investigations:
            obj_array = []
            for investigation in objects:
                investigation.id = str(investigation.id)
                obj_array.append(
                    investigation.dict(
                        exclude={
                            "file_path": True,
                        }
                    )
                )

            JsonWriter.writeJsonObject(
                os.path.join(output_path, "response_tasks.json"),
                {"response_tasks": obj_array},
            )

        elif type == SecurityContentType.lookups:
            obj_array = []
            for lookup in objects:

                obj_array.append(
                    lookup.dict(
                        exclude={
                            "file_path": True,
                        }
                    )
                )

            JsonWriter.writeJsonObject(
                os.path.join(output_path, "lookups.json"), {"lookups": obj_array}
            )

        elif type == SecurityContentType.deployments:
            obj_array = []
            for deployment in objects:
                deployment.id = str(deployment.id)
                obj_array.append(
                    deployment.dict(
                        exclude_none=True,
                        exclude={
                            "file_path": True,
                        },
                    )
                )

            JsonWriter.writeJsonObject(
                os.path.join(output_path, "deployments.json"),
                {"deployments": obj_array},
            )
