import os
import json
import pathlib

from contentctl.output.json_writer import JsonWriter
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import (
    SecurityContentObject_Abstract,
)



class ApiJsonOutput:

    def writeObjects(
        self,
        objects: list[SecurityContentObject_Abstract],
        output_path: pathlib.Path,
        app_label:str = "ESCU",
        contentType: SecurityContentType = None
    ) -> None:
        """#Serialize all objects
        try:
            for obj in objects:

                serialized_objects.append(obj.model_dump())
        except Exception as e:
            raise Exception(f"Error serializing object with name '{obj.name}' and type '{type(obj).__name__}': '{str(e)}'")
        """

        if contentType == SecurityContentType.detections:
            detections = [
                detection.model_dump(
                    include=set(
                        [
                            "name",
                            "author",
                            "date",
                            "version",
                            "id",
                            "description",
                            "tags",
                            "search",
                            "how_to_implement",
                            "known_false_positives",
                            "references",
                            "datamodel",
                            "macros",
                            "lookups",
                            "source",
                            "nes_fields",
                        ]
                    )
                )
                for detection in objects
            ]
            #Only a subset of macro fields are required:
            # for detection in detections:
            #     new_macros = []
            #     for macro in detection.get("macros",[]):
            #         new_macro_fields = {}
            #         new_macro_fields["name"] = macro.get("name")
            #         new_macro_fields["definition"] = macro.get("definition")
            #         new_macro_fields["description"] = macro.get("description")
            #         if len(macro.get("arguments", [])) > 0:
            #             new_macro_fields["arguments"] = macro.get("arguments") 
            #         new_macros.append(new_macro_fields)
            #     detection["macros"] = new_macros
            #     del()
                    
            
            JsonWriter.writeJsonObject(
                os.path.join(output_path, "detections.json"), "detections", detections
            )

        elif contentType == SecurityContentType.macros:
            macros = [
                macro.model_dump(include=set(["definition", "description", "name"]))
                for macro in objects
            ]
            for macro in macros:
                for k in ["author", "date","version","id","references"]:
                    if k in macro:
                        del(macro[k])
            JsonWriter.writeJsonObject(
                os.path.join(output_path, "macros.json"), "macros", macros
            )

        elif contentType == SecurityContentType.stories:
            stories = [
                story.model_dump(
                    include=set(
                        [
                            "name",
                            "author",
                            "date",
                            "version",
                            "id",
                            "description",
                            "narrative",
                            "references",
                            "tags",
                            "detections_names",
                            "investigation_names",
                            "baseline_names",
                            "detections",
                        ]
                    )
                )
                for story in objects
            ]
            # Only get certain fields from detections
            for story in stories:
                # Only use a small subset of fields from the detection
                story["detections"] = [
                    {
                        "name": detection["name"],
                        "source": detection["source"],
                        "type": detection["type"],
                        "tags": detection["tags"].get("mitre_attack_enrichments", []),
                    }
                    for detection in story["detections"]
                ]
                story["detection_names"] = [f"{app_label} - {name} - Rule" for name in story["detection_names"]]
                

            JsonWriter.writeJsonObject(
                os.path.join(output_path, "stories.json"), "stories", stories
            )

        elif contentType == SecurityContentType.baselines:
            try:
                baselines = [
                    baseline.model_dump(
                        include=set(
                            [
                                "name",
                                "author",
                                "date",
                                "version",
                                "id",
                                "description",
                                "type",
                                "datamodel",
                                "search",
                                "how_to_implement",
                                "known_false_positives",
                                "references",
                                "tags",
                            ]
                        )
                    )
                    for baseline in objects
                ]
            except Exception as e:
                print(e)
                print('wait')

            JsonWriter.writeJsonObject(
                    os.path.join(output_path, "baselines.json"), "baselines", baselines
                )

        elif contentType == SecurityContentType.investigations:
            investigations = [
                investigation.model_dump(
                    include=set(
                        [
                            "name",
                            "author",
                            "date",
                            "version",
                            "id",
                            "description",
                            "type",
                            "datamodel",
                            "search",
                            "how_to_implemnet",
                            "known_false_positives",
                            "references",
                            "inputs",
                            "tags",
                            "lowercase_name",
                        ]
                    )
                )
                for investigation in objects
            ]
            JsonWriter.writeJsonObject(
                os.path.join(output_path, "response_tasks.json"),
                "response_tasks",
                investigations,
            )

        elif contentType == SecurityContentType.lookups:
            lookups = [
                lookup.model_dump(
                    include=set(
                        [
                            "name",
                            "description",
                            "collection",
                            "fields_list",
                            "filename",
                            "default_match",
                            "match_type",
                            "min_matches",
                            "case_sensitive_match",
                        ]
                    )
                )
                for lookup in objects
            ]
            for lookup in lookups:
                for k in ["author","date","version","id","references"]:
                    if k in lookup:
                        del(lookup[k]) 
            JsonWriter.writeJsonObject(
                os.path.join(output_path, "lookups.json"), "lookups", lookups
            )

        elif contentType == SecurityContentType.deployments:
            deployments = [
                deployment.model_dump(
                    include=set(
                        [
                            "name",
                            "author",
                            "date",
                            "version",
                            "id",
                            "description",
                            "scheduling",
                            "rba",
                            "tags"
                        ] 
                    )
                )
                for deployment in objects
            ]
            #references are not to be included, but have been deleted in the
            #model_serialization logic
            JsonWriter.writeJsonObject(
                os.path.join(output_path, "deployments.json"),
                "deployments",
                deployments,
            )