import json
import pathlib
from typing import List, Union

VERSION = "4.5"
NAME = "Detection Coverage"
DESCRIPTION = "Security Content Detection Coverage"
DOMAIN = "enterprise-attack"


class AttackNavWriter:
    @staticmethod
    def writeAttackNavFile(
        mitre_techniques: dict[str, dict[str, Union[List[str], int]]],
        output_path: pathlib.Path,
    ) -> None:
        max_count = max(
            (technique["score"] for technique in mitre_techniques.values()), default=0
        )

        layer_json = {
            "versions": {"attack": "16", "navigator": "5.1.0", "layer": VERSION},
            "name": NAME,
            "description": DESCRIPTION,
            "domain": DOMAIN,
            "techniques": [],
            "gradient": {
                "colors": ["#ffffff", "#66b1ff", "#096ed7"],
                "minValue": 0,
                "maxValue": max_count,
            },
            "filters": {
                "platforms": [
                    "Windows",
                    "Linux",
                    "macOS",
                    "Network",
                    "AWS",
                    "GCP",
                    "Azure",
                    "Azure AD",
                    "Office 365",
                    "SaaS",
                ]
            },
            "layout": {
                "layout": "side",
                "showName": True,
                "showID": True,
                "showAggregateScores": False,
            },
            "legendItems": [
                {"label": "No detections", "color": "#ffffff"},
                {"label": "Has detections", "color": "#66b1ff"},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
        }

        for technique_id, data in mitre_techniques.items():
            links = []
            for detection_info in data["file_paths"]:
                # Split the detection info into its components
                detection_type, detection_id, detection_name = detection_info.split("|")

                # Construct research website URL (without the name)
                research_url = (
                    f"https://research.splunk.com/{detection_type}/{detection_id}/"
                )

                links.append({"label": detection_name, "url": research_url})

            layer_technique = {
                "techniqueID": technique_id,
                "score": data["score"],
                "enabled": True,
                "links": links,
            }
            layer_json["techniques"].append(layer_technique)

        with open(output_path, "w") as outfile:
            json.dump(layer_json, outfile, ensure_ascii=False, indent=4)
