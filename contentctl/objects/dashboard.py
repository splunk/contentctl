from typing import Any
from pydantic import Field, Json, model_validator

import pathlib
import copy
from jinja2 import Environment
import json
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.config import build

DEFAULT_DASHBAORD_JINJA2_TEMPLATE = '''<dashboard version="2" theme="light">
    <label>{{ dashboard.name }}</label>
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

class Dashboard(SecurityContentObject):
    j2_template: str = Field(default=DEFAULT_DASHBAORD_JINJA2_TEMPLATE, description="Jinja2 Template used to construct the dashboard")
    json_obj: Json[dict[str,Any]] = Field(..., description="Valid JSON object that describes the dashboard")
    description: str = Field(...,max_length=10000)
    

    
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
            errors.append(f"title 'json_object' is '{name_from_json}', but the name defined in the YML is '{name_from_file}'. These two must match.")
        
        
        if data.get("description",None) is not None:
            raise ValueError(f"The description field should not be defined in {yml_file_path}, is is read from {json_file_path}")
        
        description_from_json = json_obj.get("description",None)

        if description_from_json is None:
            errors.append("'description' field is missing from field 'json_object'")
        
        if len(errors) > 0 :
            err_string = "\n".join(errors)
            raise ValueError(f"Error(s) validating dashboard:\n{err_string}")
        
        data['name'] = name_from_file
        data['description'] = description_from_json        
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


