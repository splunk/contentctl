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
        raw_json = data.get("json_obj", None)
        
        try:
            json_obj = json.loads(raw_json)
        except Exception as e:
            raise ValueError(f"Error getting field 'json_obj'. Field does not contain valid JSON: {str(e)}")

        name_from_file = data.get("name",None)
        name_from_json  = json_obj.get("title",None)
        description_from_file = data.get("description",None)
        description_from_json = json_obj.get("description",None)

        errors:list[str] = []
        if name_from_json is None:
            errors.append("'title' field is missing from field 'json_object'")
        elif name_from_json is not None and name_from_file is None:
            name_from_file = name_from_json
        elif name_from_json != name_from_file:
            errors.append(f"title 'json_object' is '{name_from_json}', but the name defined in the YML is '{name_from_file}'. These two must match.")

        if description_from_json is None:
            errors.append("'description' field is missing from field 'json_object'")
        elif description_from_json is not None and description_from_file is None:
            description_from_file = description_from_file
        elif description_from_json != description_from_file:
            errors.append(f"description in 'json_object' is '{description_from_json}', but the description defined in the YML is '{description_from_file}'. These two must match.")
        
        data['name'] = name_from_json
        data['description'] = description_from_json        
        if len(errors) > 0 :
            err_string = "\n".join(errors)
            raise ValueError(f"Error(s) validating dashboard:\n{err_string}")
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


