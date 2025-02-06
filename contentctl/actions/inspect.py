import datetime
import json
import pathlib
import sys
import time
import timeit
from dataclasses import dataclass
from io import BufferedReader

from requests import Session, get, post
from requests.auth import HTTPBasicAuth

from contentctl.objects.config import inspect
from contentctl.objects.errors import (
    DetectionIDError,
    DetectionMissingError,
    MetadataValidationError,
    VersionBumpingError,
    VersionDecrementedError,
)
from contentctl.objects.savedsearches_conf import SavedsearchesConf

"""
The following list includes all appinspect tags available from:
https://dev.splunk.com/enterprise/reference/appinspect/appinspecttagreference/

This allows contentctl to be as forward-leaning as possible in catching
any potential issues on the widest variety of stacks.
"""
INCLUDED_TAGS_LIST = [
    "aarch64_compatibility",
    "ast",
    "cloud",
    "future",
    "manual",
    "packaging_standards",
    "private_app",
    "private_classic",
    "private_victoria",
    "splunk_appinspect",
]
INCLUDED_TAGS_STRING = ",".join(INCLUDED_TAGS_LIST)


@dataclass(frozen=True)
class InspectInputDto:
    config: inspect


class Inspect:
    def execute(self, config: inspect) -> str:
        if config.build_app or config.build_api:
            appinspect_token = self.inspectAppAPI(config)

            if config.enable_metadata_validation:
                self.check_detection_metadata(config)
            else:
                print("🟡 Detection metadata validation disabled, skipping.")

            return appinspect_token

        else:
            raise Exception("Inspect only supported for app and api build targets")

    def getElapsedTime(self, startTime: float) -> datetime.timedelta:
        return datetime.timedelta(seconds=round(timeit.default_timer() - startTime))

    def inspectAppAPI(self, config: inspect) -> str:
        session = Session()
        session.auth = HTTPBasicAuth(
            config.splunk_api_username, config.splunk_api_password
        )

        APPINSPECT_API_LOGIN = "https://api.splunk.com/2.0/rest/login/splunk"

        res = session.get(APPINSPECT_API_LOGIN)
        # If login failed or other failure, raise an exception
        res.raise_for_status()

        authorization_bearer = res.json().get("data", {}).get("token", None)
        APPINSPECT_API_VALIDATION_REQUEST = (
            "https://appinspect.splunk.com/v1/app/validate"
        )

        package_path = config.getPackageFilePath(include_version=False)
        if not package_path.is_file():
            raise Exception(
                f"Cannot run Appinspect API on App '{config.app.title}' - "
                f"no package exists as expected path '{package_path}'.\nAre you "
                "trying to 'contentctl deploy_acs' the package BEFORE running 'contentctl build'?"
            )

        """
        Some documentation on "files" argument for requests.post exists here:
        https://docs.python-requests.org/en/latest/api/
        The type (None, INCLUDED_TAGS_STRING) is intentional, and the None is important.
        In curl syntax, the request we make below is equivalent to
        curl -X POST \
            -H "Authorization: bearer <TOKEN>" \
            -H "Cache-Control: no-cache" \
            -F "app_package=@<PATH/APP-PACKAGE>" \
            -F "included_tags=cloud" \
            --url "https://appinspect.splunk.com/v1/app/validate"
        
        This is confirmed by the great resource:
        https://curlconverter.com/
        """
        data: dict[str, tuple[None, str] | BufferedReader] = {
            "app_package": open(package_path, "rb"),
            "included_tags": (
                None,
                INCLUDED_TAGS_STRING,
            ),  # tuple with None is intentional here
        }

        headers = {
            "Authorization": f"bearer {authorization_bearer}",
            "Cache-Control": "no-cache",
        }

        res = post(APPINSPECT_API_VALIDATION_REQUEST, files=data, headers=headers)

        res.raise_for_status()

        request_id = res.json().get("request_id", None)
        APPINSPECT_API_VALIDATION_STATUS = (
            f"https://appinspect.splunk.com/v1/app/validate/status/{request_id}"
        )

        startTime = timeit.default_timer()
        # the first time, wait for 40 seconds. subsequent times, wait for less.
        # this is because appinspect takes some time to return, so there is no sense
        # checking many times when we know it will take at least 40 seconds to run.
        iteration_wait_time = 40
        while True:
            res = get(APPINSPECT_API_VALIDATION_STATUS, headers=headers)
            res.raise_for_status()
            status = res.json().get("status", None)
            if status in ["PROCESSING", "PREPARING"]:
                print(
                    f"[{self.getElapsedTime(startTime)}] Appinspect API is {status}..."
                )
                time.sleep(iteration_wait_time)
                iteration_wait_time = 1
                continue
            elif status == "SUCCESS":
                print(
                    f"[{self.getElapsedTime(startTime)}] Appinspect API has finished!"
                )
                break
            else:
                raise Exception(f"Error - Unknown Appinspect API status '{status}'")

        # We have finished running appinspect, so get the report
        APPINSPECT_API_REPORT = (
            f"https://appinspect.splunk.com/v1/app/report/{request_id}"
        )
        # Get human-readable HTML report
        headers = headers = {
            "Authorization": f"bearer {authorization_bearer}",
            "Content-Type": "text/html",
        }
        res = get(APPINSPECT_API_REPORT, headers=headers)
        res.raise_for_status()
        report_html = res.content

        # Get JSON report for processing
        headers = headers = {
            "Authorization": f"bearer {authorization_bearer}",
            "Content-Type": "application/json",
        }
        res = get(APPINSPECT_API_REPORT, headers=headers)
        res.raise_for_status()
        report_json = res.json()

        # Just get app path here to avoid long function calls in the open() calls below
        appPath = config.getPackageFilePath(include_version=True)
        appinpect_html_path = appPath.with_suffix(
            appPath.suffix + ".appinspect_api_results.html"
        )
        appinspect_json_path = appPath.with_suffix(
            appPath.suffix + ".appinspect_api_results.json"
        )
        # Use the full path of the app, but update the suffix to include info about appinspect
        with open(appinpect_html_path, "wb") as report:
            report.write(report_html)
        with open(appinspect_json_path, "w") as report:
            json.dump(report_json, report)

        self.parseAppinspectJsonLogFile(appinspect_json_path)

        return authorization_bearer

    def inspectAppCLI(self, config: inspect) -> None:
        try:
            raise Exception(
                "Local spunk-appinspect Not Supported at this time (you may use the appinspect api). If you would like to locally inspect your app with"
                "Python 3.7, 3.8, or 3.9 (with limited support), please refer to:\n"
                "\t - https://dev.splunk.com/enterprise/docs/developapps/testvalidate/appinspect/useappinspectclitool/"
            )
            from splunk_appinspect.main import (
                APP_PACKAGE_ARGUMENT,
                EXCLUDED_TAGS_OPTION,
                INCLUDED_TAGS_OPTION,
                LOG_FILE_OPTION,
                MODE_OPTION,
                OUTPUT_FILE_OPTION,
                TEST_MODE,
                validate,
            )
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

        appinspect_output = (
            self.dist
            / f"{self.config.build.title}-{self.config.build.version}.appinspect_cli_results.json"
        )
        appinspect_logging = (
            self.dist
            / f"{self.config.build.title}-{self.config.build.version}.appinspect_cli_logging.log"
        )
        try:
            arguments_list = [
                (APP_PACKAGE_ARGUMENT, str(self.getPackagePath(include_version=False)))
            ]
            options_list = []
            options_list += [MODE_OPTION, TEST_MODE]
            options_list += [OUTPUT_FILE_OPTION, str(appinspect_output)]
            options_list += [LOG_FILE_OPTION, str(appinspect_logging)]

            # If there are any tags defined, then include them here
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
                sys.stdin = open("/dev/stdin", "r")
                print(
                    f"AppInspect passed! Please check [ {appinspect_output} , {appinspect_logging} ] for verbose information."
                )
            else:
                if sys.version.startswith("3.11") or sys.version.startswith("3.12"):
                    raise Exception(
                        "At this time, AppInspect may fail on valid apps under Python>=3.11 with "
                        "the error 'global flags not at the start of the expression at position 1'. "
                        "If you encounter this error, please run AppInspect on a version of Python "
                        "<3.11.  This issue is currently tracked. Please review the appinspect "
                        "report output above for errors."
                    )
                else:
                    raise Exception(
                        "AppInspect Failure - Please review the appinspect report output above for errors."
                    )
        finally:
            # appinspect outputs the log in json format, but does not format it to be easier
            # to read (it is all in one line). Read back that file and write it so it
            # is easier to understand

            # Note that this may raise an exception itself!
            self.parseAppinspectJsonLogFile(appinspect_output)

    def parseAppinspectJsonLogFile(
        self,
        logfile_path: pathlib.Path,
        status_types: list[str] = ["error", "failure", "manual_check", "warning"],
        exception_types: list[str] = ["error", "failure", "manual_check"],
    ) -> None:
        if not set(exception_types).issubset(set(status_types)):
            raise Exception(
                f"Error - exception_types {exception_types} MUST be a subset of status_types {status_types}, but it is not"
            )
        with open(logfile_path, "r+") as logfile:
            j = json.load(logfile)
            # Seek back to the beginning of the file. We don't need to clear
            # it sice we will always write AT LEAST the same number of characters
            # back as we read (due to the addition of whitespace)
            logfile.seek(0)
            json.dump(
                j,
                logfile,
                indent=3,
            )

        reports = j.get("reports", [])
        if len(reports) != 1:
            raise Exception("Expected to find one appinspect report but found 0")
        verbose_errors = []

        for group in reports[0].get("groups", []):
            for check in group.get("checks", []):
                if check.get("result", "") in status_types:
                    verbose_errors.append(
                        f" - {check.get('result', '')} [{group.get('name', 'NONAME')}: {check.get('name', 'NONAME')}]"
                    )
        verbose_errors.sort()

        summary = j.get("summary", None)
        if summary is None:
            raise Exception("Missing summary from appinspect report")
        msgs = []
        generated_exception = False
        for key in status_types:
            if summary.get(key, 0) > 0:
                msgs.append(f" - {summary.get(key, 0)} {key}s")
                if key in exception_types:
                    generated_exception = True
        if len(msgs) > 0 or len(verbose_errors):
            summary = "\n".join(msgs)
            details = "\n".join(verbose_errors)
            summary = f"{summary}\nDetails:\n{details}"
            if generated_exception:
                raise Exception(
                    f"AppInspect found [{','.join(exception_types)}] that MUST be addressed to pass AppInspect API:\n{summary}"
                )
            else:
                print(
                    f"AppInspect found [{','.join(status_types)}] that MAY cause a failure during AppInspect API:\n{summary}"
                )
        else:
            print("AppInspect was successful!")

        return

    def check_detection_metadata(self, config: inspect) -> None:
        """
        Using a previous build, compare the savedsearches.conf files to detect any issues w/
        detection metadata. **NOTE**: Detection metadata validation can only be performed between
        two builds with theappropriate metadata structure. In ESCU, this was added as of release
        v4.39.0, so all current and previous builds for use with this feature must be this version
        or greater.

        :param config: an inspect config
        :type config: :class:`contentctl.objects.config.inspect`
        """
        # TODO (#282): We should be inspect the same artifact we're passing around from the
        #   build stage ideally
        # Unpack the savedsearch.conf of each app package
        current_build_conf = SavedsearchesConf.init_from_package(
            package_path=config.getPackageFilePath(include_version=False),
            app_name=config.app.label,
            appid=config.app.appid,
        )
        previous_build_conf = SavedsearchesConf.init_from_package(
            package_path=config.get_previous_package_file_path(),
            app_name=config.app.label,
            appid=config.app.appid,
        )

        # Compare the conf files
        validation_errors: dict[str, list[MetadataValidationError]] = {}
        for rule_name in previous_build_conf.detection_stanzas:
            validation_errors[rule_name] = []
            # No detections should be removed from build to build
            if rule_name not in current_build_conf.detection_stanzas:
                if config.suppress_missing_content_exceptions:
                    print(
                        f"[SUPPRESSED] {DetectionMissingError(rule_name=rule_name).long_message}"
                    )
                else:
                    validation_errors[rule_name].append(
                        DetectionMissingError(rule_name=rule_name)
                    )
                continue
            # Pull out the individual stanza for readability
            previous_stanza = previous_build_conf.detection_stanzas[rule_name]
            current_stanza = current_build_conf.detection_stanzas[rule_name]

            # Detection IDs should not change
            if (
                current_stanza.metadata.detection_id
                != previous_stanza.metadata.detection_id
            ):
                validation_errors[rule_name].append(
                    DetectionIDError(
                        rule_name=rule_name,
                        current_id=current_stanza.metadata.detection_id,
                        previous_id=previous_stanza.metadata.detection_id,
                    )
                )

            # Versions should never decrement in successive builds
            if (
                current_stanza.metadata.detection_version
                < previous_stanza.metadata.detection_version
            ):
                validation_errors[rule_name].append(
                    VersionDecrementedError(
                        rule_name=rule_name,
                        current_version=current_stanza.metadata.detection_version,
                        previous_version=previous_stanza.metadata.detection_version,
                    )
                )

            # Versions need to be bumped if the stanza changes at all
            if current_stanza.version_should_be_bumped(previous_stanza):
                validation_errors[rule_name].append(
                    VersionBumpingError(
                        rule_name=rule_name,
                        current_version=current_stanza.metadata.detection_version,
                        previous_version=previous_stanza.metadata.detection_version,
                    )
                )

        # Convert our dict mapping to a flat list of errors for use in reporting
        validation_error_list = [
            x for inner_list in validation_errors.values() for x in inner_list
        ]

        # Report failure/success
        print("\nDetection Metadata Validation:")
        if len(validation_error_list) > 0:
            # Iterate over each rule and report the failures
            for rule_name in validation_errors:
                if len(validation_errors[rule_name]) > 0:
                    print(f"\t❌ {rule_name}")
                    for error in validation_errors[rule_name]:
                        print(f"\t\t🔸 {error.short_message}")
        else:
            # If no errors in the list, report success
            print(
                "\t✅ Detection metadata looks good and all versions were bumped appropriately :)"
            )

        # Raise an ExceptionGroup for all validation issues
        if len(validation_error_list) > 0:
            raise ExceptionGroup(
                "Validation errors when comparing detection stanzas in current and previous build:",
                validation_error_list,
            )
