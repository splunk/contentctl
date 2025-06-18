# Standard library imports
import json
import pathlib
from datetime import datetime
from typing import Any, TypedDict

# Third-party imports
from contentctl.objects.detection import Detection


class TechniqueData(TypedDict):
    score: int
    file_paths: list[str]
    links: list[dict[str, str]]


class LayerData(TypedDict):
    name: str
    versions: dict[str, str]
    domain: str
    description: str
    filters: dict[str, list[str]]
    sorting: int
    layout: dict[str, str | bool]
    hideDisabled: bool
    techniques: list[dict[str, Any]]
    gradient: dict[str, list[str] | int]
    legendItems: list[dict[str, str]]
    showTacticRowBackground: bool
    tacticRowBackground: str
    selectTechniquesAcrossTactics: bool
    selectSubtechniquesWithParent: bool
    selectVisibleTechniques: bool
    metadata: list[dict[str, str]]


class AttackNavOutput:
    def __init__(
        self,
        layer_name: str = "Splunk Detection Coverage",
        layer_description: str = "MITRE ATT&CK coverage for Splunk detections",
        layer_domain: str = "enterprise-attack",
    ):
        self.layer_name = layer_name
        self.layer_description = layer_description
        self.layer_domain = layer_domain

    def writeObjects(
        self, detections: list[Detection], output_path: pathlib.Path
    ) -> None:
        """
        Generate MITRE ATT&CK Navigator layer file from detections
        Args:
            detections: List of Detection objects
            output_path: Path to write the layer file
        """
        techniques: dict[str, TechniqueData] = {}
        tactic_coverage: dict[str, set[str]] = {}

        # Process each detection
        for detection in detections:
            if not hasattr(detection.tags, "mitre_attack_id"):
                continue

            for tactic in detection.tags.mitre_attack_id:
                if tactic not in techniques:
                    techniques[tactic] = {"score": 0, "file_paths": [], "links": []}
                    tactic_coverage[tactic] = set()

                detection_type = detection.source
                detection_id = str(detection.id)  # Convert UUID to string
                detection_url = (
                    f"https://research.splunk.com/{detection_type}/{detection_id}/"
                )
                detection_name = detection.name.replace(
                    "_", " "
                ).title()  # Convert to Title Case
                detection_info = f"{detection_name}"

                techniques[tactic]["score"] += 1
                techniques[tactic]["file_paths"].append(detection_info)
                techniques[tactic]["links"].append(
                    {"label": detection_name, "url": detection_url}
                )
                tactic_coverage[tactic].add(detection_id)

        # Create the layer file
        layer: LayerData = {
            "name": self.layer_name,
            "versions": {
                "attack": "17",  # Update as needed
                "navigator": "5.1.0",
                "layer": "4.5",
            },
            "domain": self.layer_domain,
            "description": self.layer_description,
            "filters": {
                "platforms": [
                    "Windows",
                    "Linux",
                    "macOS",
                    "AWS",
                    "GCP",
                    "Azure",
                    "Office 365",
                    "SaaS",
                ]
            },
            "sorting": 0,
            "layout": {
                "layout": "flat",
                "showName": True,
                "showID": False,
                "showAggregateScores": True,
                "countUnscored": True,
                "aggregateFunction": "average",
                "expandedSubtechniques": "none",
            },
            "hideDisabled": False,
            "techniques": [
                {
                    "techniqueID": tid,
                    "score": data["score"],
                    "metadata": [
                        {"name": "Detection", "value": name, "divider": False}
                        for name in data["file_paths"]
                    ]
                    + [
                        {
                            "name": "Link",
                            "value": f"[View Detection]({link['url']})",
                            "divider": False,
                        }
                        for link in data["links"]
                    ],
                    "links": [
                        {"label": link["label"], "url": link["url"]}
                        for link in data["links"]
                    ],
                }
                for tid, data in techniques.items()
            ],
            "gradient": {
                "colors": [
                    "#1a365d",  # Dark blue
                    "#2c5282",  # Medium blue
                    "#4299e1",  # Light blue
                    "#48bb78",  # Light green
                    "#38a169",  # Medium green
                    "#276749",  # Dark green
                ],
                "minValue": 0,
                "maxValue": 5,  # Adjust based on your max detections per technique
            },
            "legendItems": [
                {"label": "1 Detection", "color": "#1a365d"},
                {"label": "2 Detections", "color": "#4299e1"},
                {"label": "3 Detections", "color": "#48bb78"},
                {"label": "4+ Detections", "color": "#276749"},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": True,
            "selectVisibleTechniques": False,
            "metadata": [
                {"name": "Generated", "value": datetime.now().isoformat()},
                {"name": "Total Detections", "value": str(len(detections))},
                {"name": "Covered Techniques", "value": str(len(techniques))},
            ],
        }

        # Write the layer file
        output_file = output_path / "coverage.json"
        with open(output_file, "w") as f:
            json.dump(layer, f, indent=2)

        print(f"\n✅ MITRE ATT&CK Navigator layer file written to: {output_file}")
        print("📊 Coverage Summary:")
        print(f"   Total Detections: {len(detections)}")
        print(f"   Covered Techniques: {len(techniques)}")
        print(f"   Tactics with Coverage: {len(tactic_coverage)}")
        print("\n🗺️  To view the layer:")
        print("   1. Go to https://mitre-attack.github.io/attack-navigator/")
        print("   2. Click 'Open Existing Layer'")
        print(f"   3. Select the file: {output_file}")

    def convertNameToFileName(self, name: str) -> str:
        """Convert a detection name to a valid filename"""
        file_name = (
            name.replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            .replace("/", "_")
            .lower()
        )
        return f"{file_name}.yml"
