import datetime
import re
import os
from xmlrpc.client import APPLICATION_ERROR
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import pathlib
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.config import build

class ConfWriter():

    @staticmethod
    def writeConfFileHeader(app_output_path:pathlib.Path, config: build) -> None:
        output_path = config.getPackageDirectoryPath()/app_output_path
        utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True)

        template = j2_env.get_template('header.j2')
        output = template.render(time=utc_time, author=' - '.join([config.app.author_name,config.app.author_company]), author_email=config.app.author_email)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            output = output.encode('ascii', 'ignore').decode('ascii')
            f.write(output)


    @staticmethod
    def writeConfFileHeaderEmpty(app_output_path:pathlib.Path, config: build) -> None:
        output_path = config.getPackageDirectoryPath()/app_output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write('')


    @staticmethod
    def writeConfFile(app_output_path:pathlib.Path, template_name : str, config: build, objects : list) -> None:
        output_path = config.getPackageDirectoryPath()/app_output_path
        def custom_jinja2_enrichment_filter(string:str, object:SecurityContentObject):
            
            substitutions = re.findall(r"%[^%]*%", string)
            updated_string = string
            for sub in substitutions:
                sub_without_percents = sub.replace("%","")
                if hasattr(object, sub_without_percents):
                    updated_string = updated_string.replace(sub, str(getattr(object, sub_without_percents)))
                elif hasattr(object,'tags') and hasattr(object.tags, sub_without_percents):
                     updated_string = updated_string.replace(sub, str(getattr(object.tags, sub_without_percents)))
                else:
                    raise Exception(f"Unable to find field {sub} in object {object.name}")
            
            return updated_string


        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True,
            undefined=StrictUndefined)
        j2_env.globals.update(objectListToNameList=SecurityContentObject.objectListToNameList)


        j2_env.filters['custom_jinja2_enrichment_filter'] = custom_jinja2_enrichment_filter
        template = j2_env.get_template(template_name)
        
        output = template.render(objects=objects, APP_NAME=config.app.label)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'a') as f:
            output = output.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output)

