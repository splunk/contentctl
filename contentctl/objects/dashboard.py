from typing import Any
from pydantic import Field, Json
import pathlib
import copy
from jinja2 import Environment
import json
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.config import build

DEFAULT_DASHBAORD_JINJA2_TEMPLATE = '''<dashboard version="2" theme="light">
    <label>{{ dashboard.getLabelTag(config) }}</label>
    <description></description>
    <definition><![CDATA[
{{ dashboard.getJsonWithDescriptionAsString() }}
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


    def getOutputFilepathRelativeToAppRoot(self, config:build)->pathlib.Path:
        filename = f"{config.app.label}_{self.name}.xml".lower()
        return pathlib.Path("default/data/ui/views")/filename
    
    def getLabelTag(self, config:build)->str:
        return f"{config.app.label} - {self.name}"
    
    def getJsonWithDescriptionAsString(self)->str:
        copied_json:Json[dict[str,Any]] = copy.deepcopy(self.json_obj)
        copied_json['description']=self.description
        return json.dumps(copied_json, indent=4)
    
    def writeDashboardFile(self, j2_env:Environment, config:build):
        template = j2_env.from_string(self.j2_template)
        dashboard_text = template.render(config=config, dashboard=self)

        with open(config.getPackageDirectoryPath()/self.getOutputFilepathRelativeToAppRoot(config), 'a') as f:
            output_xml = dashboard_text.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output_xml)



    
