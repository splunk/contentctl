import re
import sys

from pydantic import ValidationError

from contentctl.objects.investigation import Investigation
from contentctl.input.yml_reader import YmlReader
from contentctl.objects.enums import SecurityContentType


class InvestigationBuilder():
    investigation: Investigation

    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        try:
            self.investigation = Investigation.parse_obj(yml_dict)
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