import json
from typing import Any


class JsonWriter:
    @staticmethod
    def writeJsonObject(
        file_path: str,
        object_name: str,
        objs: list[dict[str, Any]],
        readable_output: bool = True,
    ) -> None:
        try:
            with open(file_path, "w") as outfile:
                if readable_output:
                    # At the cost of slightly larger filesize, improve the redability significantly
                    # by sorting and indenting keys/values
                    sorted_objs = sorted(objs, key=lambda o: o["name"])
                    json.dump(
                        {object_name: sorted_objs},
                        outfile,
                        ensure_ascii=False,
                        indent=2,
                    )
                else:
                    json.dump({object_name: objs}, outfile, ensure_ascii=False)

        except Exception as e:
            raise Exception(
                f"Error serializing object to Json File '{file_path}': {str(e)}"
            )
