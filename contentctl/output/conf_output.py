from dataclasses import dataclass
import os
import glob
import shutil
import sys
import tarfile
from typing import Union
from pathlib import Path
import pathlib
import time
import timeit
import datetime
import shutil
import json
from contentctl.output.conf_writer import ConfWriter
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.config import build
from requests import Session, post, get
from requests.auth import HTTPBasicAuth

class ConfOutput:
    config: build    


    def __init__(self, config: build):
        self.config = config

        #Create the build directory if it does not exist
        config.getPackageDirectoryPath().parent.mkdir(parents=True, exist_ok=True)
        
        #Remove the app path, if it exists
        shutil.rmtree(config.getPackageDirectoryPath(), ignore_errors=True)
        
        #Copy all the template files into the app
        shutil.copytree(config.getAppTemplatePath(), config.getPackageDirectoryPath())
        

    def writeHeaders(self) -> None:
        for output_app_path in ['default/analyticstories.conf', 
                                'default/savedsearches.conf', 
                                'default/collections.conf', 
                                'default/es_investigations.conf', 
                                'default/macros.conf', 
                                'default/transforms.conf', 
                                'default/workflow_actions.conf', 
                                'default/app.conf',
                                'default/content-version.conf']:
            ConfWriter.writeConfFileHeader(pathlib.Path(output_app_path),self.config)

        
        #The contents of app.manifest are not a conf file, but json.
        #DO NOT write a header for this file type, simply create the file
        with open(self.config.getPackageDirectoryPath() / pathlib.Path('app.manifest'), 'w') as f:
            pass
            

    def writeAppConf(self):
        for output_app_path, template_name in [ ("default/app.conf", "app.conf.j2"),
                                                ("default/content-version.conf", "content-version.j2"),
                                                ("app.manifest", "app.manifest.j2")]:
            ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                    template_name,
                                    self.config,
                                    [self.config.app])

        
    def writeObjects(self, objects: list, type: SecurityContentType = None) -> None:
        if type == SecurityContentType.detections:
            for output_app_path, template_name in [ ('default/savedsearches.conf', 'savedsearches_detections.j2'),
                                                    ('default/analyticstories.conf', 'analyticstories_detections.j2'),
                                                    ('default/macros.conf', 'macros_detections.j2')]:
                ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                         template_name,
                                         self.config,
                                         objects)
        
        elif type == SecurityContentType.stories:
            ConfWriter.writeConfFile(pathlib.Path('default/analyticstories.conf'), 
                                    'analyticstories_stories.j2',
                                    self.config, objects)

        elif type == SecurityContentType.baselines:
            ConfWriter.writeConfFile(pathlib.Path('default/savedsearches.conf'),
                                    'savedsearches_baselines.j2', 
                                    self.config, objects)

        elif type == SecurityContentType.investigations:
            for output_app_path, template_name in [ ('default/savedsearches.conf', 'savedsearches_investigations.j2'),
                                                    ('default/analyticstories.conf', 'analyticstories_investigations.j2')]:
                ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                         template_name,
                                         self.config,
                                         objects)
                
            workbench_panels = []
            for investigation in objects:
                if investigation.inputs:
                    response_file_name_xml = investigation.lowercase_name + "___response_task.xml"
                    workbench_panels.append(investigation)
                    investigation.search = investigation.search.replace(">","&gt;")
                    investigation.search = investigation.search.replace("<","&lt;")
                    
                    
                    ConfWriter.writeConfFileHeaderEmpty(pathlib.Path(f'default/data/ui/panels/workbench_panel_{response_file_name_xml}'), 
                                                        self.config)
                    
                    ConfWriter.writeConfFile(   pathlib.Path(f'default/data/ui/panels/workbench_panel_{response_file_name_xml}'),
                                                'panel.j2',
                                                self.config,[investigation.search])

            for output_app_path, template_name in [ ('default/es_investigations.conf', 'es_investigations_investigations.j2'),
                                                    ('default/workflow_actions.conf', 'workflow_actions.j2')]:
                ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                            template_name,
                                            self.config,
                                            workbench_panels)

        elif type == SecurityContentType.lookups:
            for output_app_path, template_name in [ ('default/collections.conf', 'collections.j2'),
                                                    ('default/transforms.conf', 'transforms.j2')]:
                ConfWriter.writeConfFile(pathlib.Path(output_app_path),
                                            template_name,
                                            self.config,
                                            objects)
            
        
            #we want to copy all *.mlmodel files as well, not just csvs
            files = list(glob.iglob(str(self.config.path/ 'lookups/*.csv'))) + list(glob.iglob(str(self.config.path / 'lookups/*.mlmodel')))
            lookup_folder = self.config.getPackageDirectoryPath()/"lookups"
            
            # Make the new folder for the lookups 
            lookup_folder.mkdir()

            #Copy each lookup into the folder
            for lookup_name in files:
                lookup_path = pathlib.Path(lookup_name)
                if lookup_path.is_file():
                    shutil.copy(lookup_path, lookup_folder/lookup_path.name)
                else:
                    raise(Exception(f"Error copying lookup/mlmodel file.  Path {lookup_path} does not exist or is not a file."))

        elif type == SecurityContentType.macros:
            ConfWriter.writeConfFile(pathlib.Path('default/macros.conf'),
                                    'macros.j2',
                                    self.config, objects)


    def packageApp(self) -> None:
        

        # input_app_path = pathlib.Path(self.config.build.path_root)/f"{self.config.build.name}"
        
        # readme_file = pathlib.Path("README")
        # if not readme_file.is_file():
        #     raise Exception("The README file does not exist in this directory. Cannot build app.")
        # shutil.copyfile(readme_file, input_app_path/readme_file.name)
        
        
        # try:
        #     import slim
        #     use_slim = True
            
        # except Exception as e:
        #     print("Failed to import Splunk Packaging Toolkit (slim).  slim requires Python<3.10.  "
        #           "Packaging app with tar instead. This should still work, but appinspect may catch "
        #           "errors that otherwise would have been flagged by slim.")
        #     use_slim = False
        
        # if use_slim:
        #     import slim
        #     from slim.utils import SlimLogger
        #     import logging
        #     #In order to avoid significant output, only emit FATAL log messages
        #     SlimLogger.set_level(logging.ERROR)
        #     try:
        #         slim.package(source=input_app_path, output_dir=pathlib.Path(self.config.build.path_root))
        #     except SystemExit as e:
        #         raise Exception(f"Error building package with slim: {str(e)}")
        # else:
        with tarfile.open(self.config.getPackageFilePath(include_version=True), "w:gz") as app_archive:
            app_archive.add(self.config.getPackageDirectoryPath(), arcname=self.config.getPackageDirectoryPath().name) 
                       
        shutil.copy2(self.config.getPackageFilePath(include_version=True), 
                     self.config.getPackageFilePath(include_version=False), 
                     follow_symlinks=False)
        
        
    def getElapsedTime(self, startTime:float)->datetime.timedelta:
        return datetime.timedelta(seconds=round(timeit.default_timer() - startTime))
        
    def inspectAppAPI(self)->None:
        if self.config.splunk_api_username is None or self.config.splunk_api_password is None:
            return None
        session = Session()
        session.auth = HTTPBasicAuth(self.config.splunk_api_username, self.config.splunk_api_password)
        APPINSPECT_API_LOGIN = "https://api.splunk.com/2.0/rest/login/splunk"
        res = session.get(APPINSPECT_API_LOGIN)
        #If login failed or other failure, raise an exception
        res.raise_for_status()
        
        appinspect_token = res.json().get("data",{}).get("token",None)
        APPINSPECT_API_VALIDATION_REQUEST = "https://appinspect.splunk.com/v1/app/validate"
        headers = {
            "Authorization": f"bearer {appinspect_token}",
            "Cache-Control": "no-cache"
        }
        files = {
            "app_package": open(self.config.getPackageFilePath(include_version=False),"rb"),
            "included_tags":(None,"cloud")
        } 
        
        res = post(APPINSPECT_API_VALIDATION_REQUEST, headers=headers, files=files)

        res.raise_for_status()

        request_id = res.json().get("request_id",None)
        APPINSPECT_API_VALIDATION_STATUS = f"https://appinspect.splunk.com/v1/app/validate/status/{request_id}"
        headers = headers = {
            "Authorization": f"bearer {appinspect_token}"
        }
        startTime = timeit.default_timer()
        while True:
            
            res = get(APPINSPECT_API_VALIDATION_STATUS, headers=headers)
            res.raise_for_status()
            status = res.json().get("status",None)
            if status in ["PROCESSING", "PREPARING"]:
                print(f"[{self.getElapsedTime(startTime)}] Appinspect API is {status}...")
                time.sleep(15)
                continue
            elif status == "SUCCESS":
                print(f"[{self.getElapsedTime(startTime)}] Appinspect API has finished!")
                break
            else:
                raise Exception(f"Error - Unknown Appinspect API status '{status}'")
        
        

        #We have finished running appinspect, so get the report
        APPINSPECT_API_REPORT = f"https://appinspect.splunk.com/v1/app/report/{request_id}"
        #Get human-readable HTML report
        headers = headers = {
            "Authorization": f"bearer {appinspect_token}",
            "Content-Type": "text/html"
        }
        res = get(APPINSPECT_API_REPORT, headers=headers)
        res.raise_for_status()
        report_html = res.content
        
        #Get JSON report for processing
        headers = headers = {
            "Authorization": f"bearer {appinspect_token}",
            "Content-Type": "application/json"
        }
        res = get(APPINSPECT_API_REPORT, headers=headers)
        res.raise_for_status()
        report_json = res.json()
        
        appinspect_html_results = pathlib.Path(str(self.config.getPackageFilePath(include_version=True))+"appinspect_api_results.html")
        appinspect_json_results = pathlib.Path(str(self.config.getPackageFilePath(include_version=True))+"appinspect_api_results.json")
        with open(appinspect_html_results, "wb") as report:
            report.write(report_html)
        with open(appinspect_json_results, "w") as report:
            json.dump(report_json, report)
        
        
        self.parseAppinspectJsonLogFile(appinspect_json_results)
      
        return None
    
    def parseAppinspectJsonLogFile(self, logfile_path:pathlib.Path, 
                                   status_types:list[str] = ["error", "failure", "manual_check", "warning"], 
                                   exception_types = ["error","failure","manual_check"] )->None:
        if not set(exception_types).issubset(set(status_types)):
                raise Exception(f"Error - exception_types {exception_types} MUST be a subset of status_types {status_types}, but it is not")
        with open(logfile_path, "r+") as logfile:
            j = json.load(logfile)
            #Seek back to the beginning of the file. We don't need to clear
            #it sice we will always write AT LEAST the same number of characters
            #back as we read (due to the addition of whitespace)
            logfile.seek(0)
            json.dump(j, logfile, indent=3, )
            
        reports = j.get("reports", [])
        if len(reports) != 1:
            raise Exception("Expected to find one appinspect report but found 0")
        verbose_errors = []
        
        for group in reports[0].get("groups", []):
            for check in group.get("checks",[]):
                if check.get("result","") in status_types:                                    
                    verbose_errors.append(f" - {check.get('result','')} [{group.get('name','NONAME')}: {check.get('name', 'NONAME')}]")
        verbose_errors.sort()
        
        summary = j.get("summary", None)
        if summary is None:
            raise Exception("Missing summary from appinspect report")
        msgs = []
        generated_exception = False
        for key in status_types:
            if summary.get(key,0)>0:
                msgs.append(f" - {summary.get(key,0)} {key}s")
                if key in exception_types:
                    generated_exception = True
        if len(msgs)>0 or len(verbose_errors):
            summary = '\n'.join(msgs)
            details = '\n'.join(verbose_errors)
            summary = f"{summary}\nDetails:\n{details}"
            if generated_exception:
                raise Exception(f"AppInspect found [{','.join(exception_types)}] that MUST be addressed to pass AppInspect API:\n{summary}")        
            else:
                print(f"AppInspect found [{','.join(status_types)}] that MAY cause a failure during AppInspect API:\n{summary}")            
        else:
            print("AppInspect was successful!")
                
        return

    def inspectAppCLI(self)-> None:
        
        try:
            raise Exception("Local spunk-appinspect Not Supported at this time (you may use the appinspect api). If you would like to locally inspect your app with"
                  "Python 3.7, 3.8, or 3.9 (with limited support), please refer to:\n"
                  "\t - https://dev.splunk.com/enterprise/docs/developapps/testvalidate/appinspect/useappinspectclitool/")
            from splunk_appinspect.main import (
                validate, MODE_OPTION, APP_PACKAGE_ARGUMENT, OUTPUT_FILE_OPTION, 
                LOG_FILE_OPTION, INCLUDED_TAGS_OPTION, EXCLUDED_TAGS_OPTION, 
                PRECERT_MODE, TEST_MODE)
        except Exception as e:
            print(e)
            # print("******WARNING******")
            # if sys.version_info.major == 3 and sys.version_info.minor > 9:
            #     print("The package splunk-appinspect was not installed due to a current issue with the library on Python3.10+.  "
            #           "Please use the following commands to set up a virtualenvironment in a different folder so you may run appinspect manually (if desired):"
            #           "\n\tpython3.9 -m venv .venv" 
            #           "\n\tsource .venv/bin/activate"
            #           "\n\tpython3 -m pip install splunk-appinspect"
            #           f"\n\tsplunk-appinspect inspect {self.getPackagePath(include_version=False).relative_to(pathlib.Path('.').absolute())} --mode precert")    
                
            # else:
            #     print("splunk-appinspect is only compatable with Python3.9 at this time.  Please see the following open issue here: https://github.com/splunk/contentctl/issues/28")
            # print("******WARNING******")
            return

        # Note that all tags are available and described here:
        # https://dev.splunk.com/enterprise/reference/appinspect/appinspecttagreference/ 
        # By default, precert mode will run ALL checks.  Explicitly included or excluding tags will 
        # change this behavior. To give the most thorough inspection, we leave these empty so that
        # ALL checks are run
        included_tags = []
        excluded_tags = []

        appinspect_output = self.dist/f"{self.config.build.title}-{self.config.build.version}.appinspect_cli_results.json"
        appinspect_logging = self.dist/f"{self.config.build.title}-{self.config.build.version}.appinspect_cli_logging.log"
        try:
            arguments_list = [(APP_PACKAGE_ARGUMENT, str(self.getPackagePath(include_version=False)))]
            options_list = []
            options_list += [MODE_OPTION, TEST_MODE]
            options_list += [OUTPUT_FILE_OPTION, str(appinspect_output)]
            options_list += [LOG_FILE_OPTION, str(appinspect_logging)]
            
            #If there are any tags defined, then include them here
            for opt in included_tags:
                options_list += [INCLUDED_TAGS_OPTION, opt]
            for opt in excluded_tags:
                options_list += [EXCLUDED_TAGS_OPTION, opt]

            cmdline = options_list + [arg[1] for arg in arguments_list]        
            validate(cmdline)
    
        except SystemExit as e:
            if e.code == 0:
                # The sys.exit called inside of appinspect validate closes stdin.  We need to
                # reopen it.
                sys.stdin = open("/dev/stdin","r")
                print(f"AppInspect passed! Please check [ {appinspect_output} , {appinspect_logging} ] for verbose information.")
            else:
                if sys.version.startswith('3.11') or sys.version.startswith('3.12'):
                    raise Exception("At this time, AppInspect may fail on valid apps under Python>=3.11 with " 
                                    "the error 'global flags not at the start of the expression at position 1'. "  
                                    "If you encounter this error, please run AppInspect on a version of Python "
                                    "<3.11.  This issue is currently tracked. Please review the appinspect "
                                    "report output above for errors.")
                else: 
                    raise Exception("AppInspect Failure - Please review the appinspect report output above for errors.")        
        finally:
                # appinspect outputs the log in json format, but does not format it to be easier
                # to read (it is all in one line). Read back that file and write it so it
                # is easier to understand
                
                #Note that this may raise an exception itself!
                self.parseAppinspectJsonLogFile(appinspect_output)
                