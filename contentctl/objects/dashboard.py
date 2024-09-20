from typing import Any
from pydantic import Field, Json, model_validator

import pathlib
from jinja2 import Environment
import json
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.config import build
from enum import StrEnum

DEFAULT_DASHBAORD_JINJA2_TEMPLATE = '''<dashboard version="2" theme="{{ dashboard.theme }}">
    <label>{{ dashboard.label(config) }}</label>
    <description></description>
    <definition><![CDATA[
{{ dashboard.pretty_print_json_obj() }}
    ]]></definition>
    <meta type="hiddenElements"><![CDATA[
{
	"hideEdit": false,
	"hideOpenInSearch": false,
	"hideExport": false
}
    ]]></meta>
</dashboard>'''

class DashboardTheme(StrEnum):
    light = "light"
    dark = "dark"

class Dashboard(SecurityContentObject):
    j2_template: str = Field(default=DEFAULT_DASHBAORD_JINJA2_TEMPLATE, description="Jinja2 Template used to construct the dashboard")
    description: str = Field(...,description="A description of the dashboard. This does not have to match "
                             "the description of the dashboard in the JSON file.", max_length=10000)
    theme: DashboardTheme = Field(default=DashboardTheme.light, description="The theme of the dashboard. Choose between 'light' and 'dark'.")
    json_obj: Json[dict[str,Any]] = Field(..., description="Valid JSON object that describes the dashboard")
    
    
    
    def label(self, config:build)->str:
        return f"{config.app.label} - {self.name}"
    
    @model_validator(mode="before")
    @classmethod
    def validate_fields_from_json(cls, data:Any)->Any:
        yml_file_name:str|None = data.get("file_path", None)
        if yml_file_name is None:
            raise ValueError("File name not passed to dashboard constructor")
        yml_file_path = pathlib.Path(yml_file_name)
        json_file_path = yml_file_path.with_suffix(".json")

        if not json_file_path.is_file():
            raise ValueError(f"Required file {json_file_path} does not exist.")
        
        with open(json_file_path,'r') as jsonFilePointer:
            try:
                json_obj:dict[str,Any] = json.load(jsonFilePointer)
            except Exception as e:
                raise ValueError(f"Unable to load data from {json_file_path}: {str(e)}")

        name_from_file = data.get("name",None)
        name_from_json  = json_obj.get("title",None)

        errors:list[str] = []
        if name_from_json is None:
            errors.append(f"'title' field is missing from {json_file_path}")
        elif name_from_json != name_from_file:
            errors.append(f"The 'title' field in the JSON file [{json_file_path}] does not match the 'name' field in the YML object [{yml_file_path}]. These two MUST match:\n    "
                          f"title in JSON : {name_from_json}\n    "
                          f"title in YML  : {name_from_file}\n    ")
        
        description_from_json = json_obj.get("description",None)
        if description_from_json is None:
            errors.append("'description' field is missing from field 'json_object'")
        
        if len(errors) > 0 :
            err_string = "\n  - ".join(errors)
            raise ValueError(f"Error(s) validating dashboard:\n  - {err_string}")
        
        data['name'] = name_from_file
        data['json_obj'] = json.dumps(json_obj)
        return data

    
    def pretty_print_json_obj(self):
        return json.dumps(self.json_obj, indent=4)
    
    def getOutputFilepathRelativeToAppRoot(self, config:build)->pathlib.Path:
        filename = f"{self.file_path.stem}.xml".lower()
        return pathlib.Path("default/data/ui/views")/filename
    
    
    def writeDashboardFile(self, j2_env:Environment, config:build):
        template = j2_env.from_string(self.j2_template)
        dashboard_text = template.render(config=config, dashboard=self)

        with open(config.getPackageDirectoryPath()/self.getOutputFilepathRelativeToAppRoot(config), 'a') as f:
            output_xml = dashboard_text.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output_xml)


