
import yaml


class DetectionWriter:

    @staticmethod
    def writeYmlFile(file_path : str, obj : dict) -> None:

        new_obj = dict()
        new_obj["name"] = obj["name"]
        new_obj["id"] = obj["id"]
        new_obj["version"] = obj["version"]
        new_obj["date"] = obj["date"]
        new_obj["author"] = obj["author"]
        new_obj["type"] = obj["type"]
        new_obj["status"] = obj["status"]
        new_obj["description"] = obj["description"]
        new_obj["data_source"] = obj["data_source"]
        new_obj["search"] = obj["search"]
        new_obj["how_to_implement"] = obj["how_to_implement"]
        new_obj["known_false_positives"] = obj["known_false_positives"]
        new_obj["references"] = obj["references"]
        new_obj["tags"] = obj["tags"]
        new_obj["tests"] = obj["tests"]

        with open(file_path, 'w') as outfile:
            yaml.safe_dump(new_obj, outfile, default_flow_style=False, sort_keys=False)