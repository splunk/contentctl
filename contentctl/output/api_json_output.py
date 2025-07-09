from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contentctl.objects.baseline import Baseline
    from contentctl.objects.deployment import Deployment
    from contentctl.objects.detection import Detection
    from contentctl.objects.investigation import Investigation
    from contentctl.objects.lookup import Lookup
    from contentctl.objects.macro import Macro
    from contentctl.objects.story import Story

import os
import pathlib

from contentctl.output.json_writer import JsonWriter

JSON_API_VERSION = 2


class ApiJsonOutput:
    output_path: pathlib.Path
    app_label: str

    def __init__(self, output_path: pathlib.Path, app_label: str):
        self.output_path = output_path
        self.app_label = app_label

    def writeDetections(
        self,
        objects: list[Detection],
    ) -> None:
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
                        "rba",
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
        # Only a subset of macro fields are required:
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
            os.path.join(self.output_path, f"detections_v{JSON_API_VERSION}.json"),
            "detections",
            detections,
        )

    def writeMacros(
        self,
        objects: list[Macro],
    ) -> None:
        macros = [
            macro.model_dump(include=set(["definition", "description", "name"]))
            for macro in objects
        ]
        for macro in macros:
            for k in ["author", "date", "version", "id", "references"]:
                if k in macro:
                    del macro[k]
        JsonWriter.writeJsonObject(
            os.path.join(self.output_path, f"macros_v{JSON_API_VERSION}.json"),
            "macros",
            macros,
        )

    def writeStories(
        self,
        objects: list[Story],
    ) -> None:
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
            story["detection_names"] = [
                f"{self.app_label} - {name} - Rule" for name in story["detection_names"]
            ]

        JsonWriter.writeJsonObject(
            os.path.join(self.output_path, f"stories_v{JSON_API_VERSION}.json"),
            "stories",
            stories,
        )

    def writeBaselines(
        self,
        objects: list[Baseline],
    ) -> None:
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

        JsonWriter.writeJsonObject(
            os.path.join(self.output_path, f"baselines_v{JSON_API_VERSION}.json"),
            "baselines",
            baselines,
        )

    def writeInvestigations(
        self,
        objects: list[Investigation],
    ) -> None:
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
            os.path.join(self.output_path, f"response_tasks_v{JSON_API_VERSION}.json"),
            "response_tasks",
            investigations,
        )

    def writeLookups(
        self,
        objects: list[Lookup],
    ) -> None:
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
            for k in ["author", "date", "version", "id", "references"]:
                if k in lookup:
                    del lookup[k]
        JsonWriter.writeJsonObject(
            os.path.join(self.output_path, f"lookups_v{JSON_API_VERSION}.json"),
            "lookups",
            lookups,
        )

    def writeDeployments(
        self,
        objects: list[Deployment],
    ) -> None:
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
                        "tags",
                    ]
                )
            )
            for deployment in objects
        ]
        # references are not to be included, but have been deleted in the
        # model_serialization logic
        JsonWriter.writeJsonObject(
            os.path.join(self.output_path, f"deployments_v{JSON_API_VERSION}.json"),
            "deployments",
            deployments,
        )
