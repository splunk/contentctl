import sys


from dataclasses import dataclass

import pathlib
import json
import datetime


from contentctl.objects.config import inspect
from requests import Session, post, get
from requests.auth import HTTPBasicAuth
import timeit
import time
@dataclass(frozen=True)
class InspectInputDto:
    config:inspect


class Inspect:

    def execute(self, config: inspect) -> str:
        if config.build_app or config.build_api:    
         
            self.inspectAppCLI(config)
            appinspect_token = self.inspectAppAPI(config)
            
            
            return appinspect_token

        else:
            raise Exception("Inspect only supported for app and api build targets")    
    
    def getElapsedTime(self, startTime:float)->datetime.timedelta:
        return datetime.timedelta(seconds=round(timeit.default_timer() - startTime))


    def inspectAppAPI(self, config: inspect)->str:
        session = Session()
        session.auth = HTTPBasicAuth(config.splunk_api_username, config.splunk_api_password)
        if config.stack_type not in ['victoria', 'classic']:
            raise Exception(f"stack_type MUST be either 'classic' or 'victoria', NOT '{config.stack_type}'")
        
        APPINSPECT_API_LOGIN = "https://api.splunk.com/2.0/rest/login/splunk"
        
            
        
        res = session.get(APPINSPECT_API_LOGIN)
        #If login failed or other failure, raise an exception
        res.raise_for_status()
        
        authorization_bearer = res.json().get("data",{}).get("token",None)
        APPINSPECT_API_VALIDATION_REQUEST = "https://appinspect.splunk.com/v1/app/validate"
        headers = {
            "Authorization": f"bearer {authorization_bearer}",
            "Cache-Control": "no-cache"
        }
        
        package_path = config.getPackageFilePath(include_version=False)
        if not package_path.is_file():
            raise Exception(f"Cannot run Appinspect API on App '{config.app.title}' - "
                            f"no package exists as expected path '{package_path}'.\nAre you "
                            "trying to 'contentctl deploy_acs' the package BEFORE running 'contentctl build'?")
        
        files = {
            "app_package": open(package_path,"rb"),
            "included_tags":(None,"cloud")
        } 
        
        res = post(APPINSPECT_API_VALIDATION_REQUEST, headers=headers, files=files)

        res.raise_for_status()

        request_id = res.json().get("request_id",None)
        APPINSPECT_API_VALIDATION_STATUS = f"https://appinspect.splunk.com/v1/app/validate/status/{request_id}?included_tags=private_{config.stack_type}"
        headers = headers = {
            "Authorization": f"bearer {authorization_bearer}"
        }
        startTime = timeit.default_timer()
        # the first time, wait for 40 seconds. subsequent times, wait for less.
        # this is because appinspect takes some time to return, so there is no sense
        # checking many times when we know it will take at least 40 seconds to run.
        iteration_wait_time = 40
        while True:
            
            res = get(APPINSPECT_API_VALIDATION_STATUS, headers=headers)
            res.raise_for_status()
            status = res.json().get("status",None)
            if status in ["PROCESSING", "PREPARING"]:
                print(f"[{self.getElapsedTime(startTime)}] Appinspect API is {status}...")
                time.sleep(iteration_wait_time)
                iteration_wait_time = 1
                continue
            elif status == "SUCCESS":
                print(f"[{self.getElapsedTime(startTime)}] Appinspect API has finished!")
                break
            else:
                raise Exception(f"Error - Unknown Appinspect API status '{status}'")
        
        

        #We have finished running appinspect, so get the report
        APPINSPECT_API_REPORT = f"https://appinspect.splunk.com/v1/app/report/{request_id}?included_tags=private_{config.stack_type}"
        #Get human-readable HTML report
        headers = headers = {
            "Authorization": f"bearer {authorization_bearer}",
            "Content-Type": "text/html"
        }
        res = get(APPINSPECT_API_REPORT, headers=headers)
        res.raise_for_status()
        report_html = res.content
        
        #Get JSON report for processing
        headers = headers = {
            "Authorization": f"bearer {authorization_bearer}",
            "Content-Type": "application/json"
        }
        res = get(APPINSPECT_API_REPORT, headers=headers)
        res.raise_for_status()
        report_json = res.json()
        
        # Just get app path here to avoid long function calls in the open() calls below
        appPath = config.getPackageFilePath(include_version=True)
        appinpect_html_path = appPath.with_suffix(appPath.suffix+".appinspect_api_results.html")
        appinspect_json_path = appPath.with_suffix(appPath.suffix+".appinspect_api_results.json")
        #Use the full path of the app, but update the suffix to include info about appinspect
        with open(appinpect_html_path, "wb") as report:
            report.write(report_html)
        with open(appinspect_json_path, "w") as report:
            json.dump(report_json, report)
        
        
        self.parseAppinspectJsonLogFile(appinspect_json_path)
      

        return authorization_bearer
    
    
    def inspectAppCLI(self, config:inspect)-> None:
        
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
