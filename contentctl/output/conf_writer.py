import datetime
import os
from xmlrpc.client import APPLICATION_ERROR
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import pathlib
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.config import Config

class ConfWriter():

    @staticmethod
    def writeConfFileHeader(output_path:pathlib.Path, config: Config) -> None:
        utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True)

        template = j2_env.get_template('header.j2')
        output = template.render(time=utc_time, author=' - '.join([config.build.author_name,config.build.author_company]), author_email=config.build.author_email)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            output = output.encode('ascii', 'ignore').decode('ascii')
            f.write(output)


    @staticmethod
    def writeConfFileHeaderEmpty(output_path:pathlib.Path, config: Config) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write('')


    @staticmethod
    def writeConfFile(output_path:pathlib.Path, template_name : str, config: Config, objects : list) -> None:
        def custom_jinja2_enrichment_filter(string, object):
            customized_string = string

            for key in dir(object):
                if type(key) is not str:
                    key = key.decode()
                if not key.startswith('__') and not key == "_abc_impl" and not callable(getattr(object, key)):
                    if hasattr(object, key):
                        customized_string = customized_string.replace("%" + key + "%", str(getattr(object, key)))

            for key in dir(object.tags):
                if type(key) is not str:
                    key = key.decode()
                if not key.startswith('__') and not key == "_abc_impl" and not callable(getattr(object.tags, key)):
                    if hasattr(object.tags, key):
                        customized_string = customized_string.replace("%" + key + "%", str(getattr(object.tags, key)))

            return customized_string

        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True,
            undefined=StrictUndefined)


        j2_env.filters['custom_jinja2_enrichment_filter'] = custom_jinja2_enrichment_filter
        template = j2_env.get_template(template_name)
        output = template.render(objects=objects, APP_NAME=config.build.name)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'a') as f:
            output = output.encode('ascii', 'ignore').decode('ascii')
            f.write(output)

