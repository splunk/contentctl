import yaml
from typing import Any
from enum import StrEnum, IntEnum

# Set the following so that we can write StrEnum and IntEnum
# to files. Otherwise, we will get the following errors when trying
# to write to files:
# yaml.representer.RepresenterError: ('cannot represent an object',.....
yaml.SafeDumper.add_multi_representer(
    StrEnum, yaml.representer.SafeRepresenter.represent_str
)

yaml.SafeDumper.add_multi_representer(
    IntEnum, yaml.representer.SafeRepresenter.represent_int
)


class YmlWriter:
    @staticmethod
    def writeYmlFile(file_path: str, obj: dict[Any, Any]) -> None:
        with open(file_path, "w") as outfile:
            yaml.safe_dump(obj, outfile, default_flow_style=False, sort_keys=False)

    @staticmethod
    def writeDetection(file_path: str, obj: dict[Any, Any]) -> None:
        output = dict()
        output["name"] = obj["name"]
        output["id"] = obj["id"]
        output["version"] = obj["version"]
        output["date"] = obj["date"]
        output["author"] = obj["author"]
        output["type"] = obj["type"]
        output["status"] = obj["status"]
        output["data_source"] = obj["data_sources"]
        output["description"] = obj["description"]
        output["search"] = obj["search"]
        output["how_to_implement"] = obj["how_to_implement"]
        output["known_false_positives"] = obj["known_false_positives"]
        output["references"] = obj["references"]
        output["tags"] = obj["tags"]
        output["tests"] = obj["tags"]

        YmlWriter.writeYmlFile(file_path=file_path, obj=output)

    @staticmethod
    def writeStory(file_path: str, obj: dict[Any, Any]) -> None:
        output = dict()
        output["name"] = obj["name"]
        output["id"] = obj["id"]
        output["version"] = obj["version"]
        output["date"] = obj["date"]
        output["author"] = obj["author"]
        output["description"] = obj["description"]
        output["narrative"] = obj["narrative"]
        output["references"] = obj["references"]
        output["tags"] = obj["tags"]

        YmlWriter.writeYmlFile(file_path=file_path, obj=output)
