import re
import sys

from pydantic import ValidationError

from bin.objects.investigation import Investigation
from bin.input.yml_reader import YmlReader
from bin.objects.enums import SecurityContentType


class InvestigationBuilder():
    investigation: Investigation
    check_references: bool

    def __init__(self, check_references: bool = False):
        self.check_references = check_references

    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        try:
            yml_dict["check_references"] = self.check_references
            self.investigation = Investigation.parse_obj(yml_dict)
            del(yml_dict["check_references"])
        except ValidationError as e:
            print('Validation Error for file ' + path)
            print(e)
            sys.exit(1)

    def reset(self) -> None:
        self.investigation = None


    def getObject(self) -> Investigation:
        return self.investigation


    def addInputs(self) -> None:
        pattern = r"\$([^\s.]*)\$"
        inputs = []

        for input in re.findall(pattern, self.investigation.search):
            inputs.append(input)

        self.investigation.inputs = inputs

    
    def addLowercaseName(self) -> None:
        self.investigation.lowercase_name = self.investigation.name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower().replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()