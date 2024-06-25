from typing import Any
import datetime
import re
import os
import json
import configparser
from xmlrpc.client import APPLICATION_ERROR
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import pathlib
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.config import build
import xml.etree.ElementTree as ET

class ConfWriter():

    @staticmethod
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
    
    @staticmethod
    def escapeNewlines(obj:Any):
        # Ensure that any newlines that occur in a string are escaped with a \.
        # Failing to do so will result in an improperly formatted conf files that
        # cannot be parsed
        if isinstance(obj,str):
            return obj.replace(f"\n"," \\\n")
        else:
            return obj


    @staticmethod
    def writeConfFileHeader(app_output_path:pathlib.Path, config: build) -> pathlib.Path:
        output = ConfWriter.writeFileHeader(app_output_path, config)    
        
        output_path = config.getPackageDirectoryPath()/app_output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            output = output.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output)

        #Ensure that the conf file we just generated/update is syntactically valid
        ConfWriter.validateConfFile(output_path)        
        return output_path

    @staticmethod
    def writeManifestFile(app_output_path:pathlib.Path, template_name : str, config: build, objects : list) -> pathlib.Path:
        j2_env = ConfWriter.getJ2Environment()
        template = j2_env.get_template(template_name)
        
        output = template.render(objects=objects, APP_NAME=config.app.label, currentDate=datetime.datetime.now(datetime.UTC).date().isoformat())
        
        output_path = config.getPackageDirectoryPath()/app_output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            output = output.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output)
        return output_path


    @staticmethod
    def writeFileHeader(app_output_path:pathlib.Path, config: build) -> str:
        #Do not output microseconds or +00:000 at the end of the datetime string
        utc_time = datetime.datetime.now(datetime.UTC).replace(microsecond=0,tzinfo=None).isoformat()
    
        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True)

        template = j2_env.get_template('header.j2')
        output = template.render(time=utc_time, author=' - '.join([config.app.author_name,config.app.author_company]), author_email=config.app.author_email)
        
        return output



    @staticmethod
    def writeXmlFile(app_output_path:pathlib.Path, template_name : str, config: build, objects : list) -> None:
        
        
        j2_env = ConfWriter.getJ2Environment()
        template = j2_env.get_template(template_name)
        
        output = template.render(objects=objects, APP_NAME=config.app.label)
        
        output_path = config.getPackageDirectoryPath()/app_output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'a') as f:
            output = output.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output)
        
        #Ensure that the conf file we just generated/update is syntactically valid
        ConfWriter.validateXmlFile(output_path) 

    


    @staticmethod
    def writeXmlFileHeader(app_output_path:pathlib.Path, config: build) -> None:
        output = ConfWriter.writeFileHeader(app_output_path, config)    
        output_with_xml_comment = f"<!--\n{output}-->\n"

        output_path = config.getPackageDirectoryPath()/app_output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            output_with_xml_comment = output_with_xml_comment.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output_with_xml_comment)
        
        # We INTENTIONALLY do not validate the comment we wrote to the header.  This is because right now,
        # the file is an empty XML document (besides the commented header). This means that it will FAIL validation 


    @staticmethod
    def getJ2Environment()->Environment:
        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True,
            undefined=StrictUndefined)
        j2_env.globals.update(objectListToNameList=SecurityContentObject.objectListToNameList)


        j2_env.filters['custom_jinja2_enrichment_filter'] = ConfWriter.custom_jinja2_enrichment_filter
        j2_env.filters['escapeNewlines'] = ConfWriter.escapeNewlines
        return j2_env

    @staticmethod
    def writeConfFile(app_output_path:pathlib.Path, template_name : str, config: build, objects : list) -> pathlib.Path:
        output_path = config.getPackageDirectoryPath()/app_output_path
        j2_env = ConfWriter.getJ2Environment()
        
        template = j2_env.get_template(template_name)
        output = template.render(objects=objects, APP_NAME=config.app.label)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'a') as f:
            output = output.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output)
        return output_path
        
        
    @staticmethod
    def validateConfFile(path:pathlib.Path):
        """Ensure that the conf file is valid.  We will do this by reading back
        the conf using RawConfigParser to ensure that it does not throw any parsing errors.
        This is particularly relevant because newlines contained in string fields may
        break the formatting of the conf file if they have been incorrectly escaped with
        the 'ConfWriter.escapeNewlines()' function. 

        If a conf file failes validation, we will throw an exception

        Args:
            path (pathlib.Path): path to the conf file to validate
        """
        return
        if path.suffix != ".conf":
            #there may be some other files built, so just ignore them
            return
        try:
            _ = configparser.RawConfigParser().read(path)
        except Exception as e:
            raise Exception(f"Failed to validate .conf file {str(path)}: {str(e)}")

    @staticmethod
    def validateXmlFile(path:pathlib.Path):
        """Ensure that the XML file is valid XML.

        Args:
            path (pathlib.Path): path to the xml file to validate
        """        
        
        try:
            with open(path, 'r') as xmlFile:
                _ = ET.fromstring(xmlFile.read())
        except Exception as e:
            raise Exception(f"Failed to validate .xml file {str(path)}: {str(e)}")
    

    @staticmethod
    def validateManifestFile(path:pathlib.Path):
        """Ensure that the Manifest file is valid JSON.

        Args:
            path (pathlib.Path): path to the manifest JSON file to validate
        """        
        return
        try:
            with open(path, 'r') as manifestFile:
                _ = json.load(manifestFile)
        except Exception as e:
            raise Exception(f"Failed to validate .manifest file {str(path)} (Note that .manifest files should contain only valid JSON-formatted data): {str(e)}")
            




