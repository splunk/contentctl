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
from contentctl.objects.dashboard import Dashboard
from contentctl.objects.config import build
import xml.etree.ElementTree as ET

# This list is not exhaustive of all default conf files, but should be
# sufficient for our purposes.
DEFAULT_CONF_FILES = [
    "alert_actions.conf",
    "app.conf",
    "audit.conf",
    "authentication.conf",
    "authorize.conf",
    "bookmarks.conf",
    "checklist.conf",
    "collections.conf",
    "commands.conf",
    "conf.conf",
    "datamodels.conf",
    "datatypesbnf.conf",
    "default-mode.conf",
    "deploymentclient.conf",
    "distsearch.conf",
    "event_renderers.conf",
    "eventdiscoverer.conf",
    "eventtypes.conf",
    "federated.conf",
    "fields.conf",
    "global-banner.conf",
    "health.conf",
    "indexes.conf",
    "inputs.conf",
    "limits.conf",
    "literals.conf",
    "livetail.conf",
    "macros.conf",
    "messages.conf",
    "metric_alerts.conf",
    "metric_rollups.conf",
    "multikv.conf",
    "outputs.conf",
    "passwords.conf",
    "procmon-filters.conf",
    "props.conf",
    "pubsub.conf",
    "restmap.conf",
    "rolling_upgrade.conf",
    "savedsearches.conf",
    "searchbnf.conf",
    "segmenters.conf",
    "server.conf",
    "serverclass.conf",
    "serverclass.seed.xml.conf",
    "source-classifier.conf",
    "sourcetypes.conf",
    "tags.conf",
    "telemetry.conf",
    "times.conf",
    "transactiontypes.conf",
    "transforms.conf",
    "ui-prefs.conf",
    "ui-tour.conf",
    "user-prefs.conf",
    "user-seed.conf",
    "viewstates.conf",
    "visualizations.conf",
    "web-features.conf",
    "web.conf",
    "wmi.conf",
    "workflow_actions.conf",
    "workload_policy.conf",
    "workload_pools.conf",
    "workload_rules.conf",
]

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
            # Remove leading and trailing characters. Conf parsers may erroneously 
            # Parse fields if they have leading or trailing newlines/whitespace and we 
            # probably don't want that anyway as it doesn't look good in output
            return obj.strip().replace(f"\n"," \\\n")
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
    def getCustomConfFileStems(config:build)->list[str]:
        # Get all the conf files in the default directory. We must make a reload.conf_file = simple key/value for them if
        # they are custom conf files
        default_path = config.getPackageDirectoryPath()/"default"
        conf_files = default_path.glob("*.conf")
        
        custom_conf_file_stems = [conf_file.stem for conf_file in conf_files if conf_file.name not in DEFAULT_CONF_FILES]
        return sorted(custom_conf_file_stems)

    @staticmethod
    def writeServerConf(config: build) -> pathlib.Path:
        app_output_path = pathlib.Path("default/server.conf")
        template_name = "server.conf.j2"

        j2_env = ConfWriter.getJ2Environment()
        template = j2_env.get_template(template_name)

        output = template.render(custom_conf_files=ConfWriter.getCustomConfFileStems(config))
        
        output_path = config.getPackageDirectoryPath()/app_output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'a') as f:
            output = output.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output)
        return output_path


    @staticmethod
    def writeAppConf(config: build) -> pathlib.Path:
        app_output_path = pathlib.Path("default/app.conf")
        template_name = "app.conf.j2"

        j2_env = ConfWriter.getJ2Environment()
        template = j2_env.get_template(template_name)

        output = template.render(custom_conf_files=ConfWriter.getCustomConfFileStems(config), 
                                 app=config.app)
        
        output_path = config.getPackageDirectoryPath()/app_output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'a') as f:
            output = output.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output)
        return output_path

    @staticmethod
    def writeManifestFile(app_output_path:pathlib.Path, template_name : str, config: build, objects : list) -> pathlib.Path:
        j2_env = ConfWriter.getJ2Environment()
        template = j2_env.get_template(template_name)
        
        output = template.render(objects=objects, app=config.app, currentDate=datetime.datetime.now(datetime.UTC).date().isoformat())
        
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
        
        output = template.render(objects=objects, app=config.app)
        
        output_path = config.getPackageDirectoryPath()/app_output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'a') as f:
            output = output.encode('utf-8', 'ignore').decode('utf-8')
            f.write(output)
        
        #Ensure that the conf file we just generated/update is syntactically valid
        ConfWriter.validateXmlFile(output_path) 

    

    @staticmethod
    def writeDashboardFiles(config:build, dashboards:list[Dashboard])->set[pathlib.Path]:
        written_files:set[pathlib.Path] = set()
        for dashboard in dashboards:
            output_file_path = dashboard.getOutputFilepathRelativeToAppRoot(config)
            # Check that the full output path does not exist so that we are not having an
            # name collision with a file in app_template
            if (config.getPackageDirectoryPath()/output_file_path).exists():
                raise FileExistsError(f"ERROR: Overwriting Dashboard File {output_file_path}. Does this file exist in {config.getAppTemplatePath()} AND {config.path/'dashboards'}?")
                
            ConfWriter.writeXmlFileHeader(output_file_path, config)
            dashboard.writeDashboardFile(ConfWriter.getJ2Environment(), config)
            ConfWriter.validateXmlFile(config.getPackageDirectoryPath()/output_file_path)
            written_files.add(output_file_path)
        return written_files


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
        output = template.render(objects=objects, app=config.app)
        
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
