from __future__ import annotations

import re
import pathlib
from pydantic import validator, root_validator
from typing import Union

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.config import ConfigDetectionConfiguration
from contentctl.objects.unit_test import UnitTest
from contentctl.objects.integration_test import IntegrationTest
from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.baseline import Baseline
from contentctl.objects.playbook import Playbook
from contentctl.helper.link_validator import LinkValidator
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.test_group import TestGroup

class Detection_Abstract(SecurityContentObject):
    # contentType: SecurityContentType = SecurityContentType.detections
    # NOTE: because `use_enum_values` is configured, this will actually be type str
    type: AnalyticsType = ...
    file_path: str = None
    # status field is REQUIRED (the way to denote this with pydantic is ...)
    status: DetectionStatus = ...
    data_source: list[str]
    tags: DetectionTags
    search: Union[str, dict]
    how_to_implement: str
    known_false_positives: str
    check_references: bool = False
    references: list

    tests: list[Union[UnitTest, IntegrationTest]] = []

    # enrichments
    datamodel: list = None
    deployment: ConfigDetectionConfiguration = None
    annotations: dict = None
    risk: list = None
    playbooks: list[Playbook] = []
    baselines: list[Baseline] = []
    mappings: dict = None
    macros: list[Macro] = []
    lookups: list[Lookup] = []
    cve_enrichment: list = None
    splunk_app_enrichment: list = None

    source: str = None
    nes_fields: str = None
    providing_technologies: list = None
    runtime: str = None
    enabled_by_default: bool = False

    class Config:
        use_enum_values = True


    # A list of groups of tests, relying on the same data
    test_groups: Union[list[TestGroup], None] = None

    @validator("test_groups", always=True)
    def validate_test_groups(cls, value, values) -> Union[list[TestGroup], None]:
        """
        Validates the `test_groups` field and constructs the model from the list of unit tests
        if no explicit construct was provided
        :param value: the value of the field `test_groups`
        :param values: a dict of the other fields in the Detection model
        """
        # if the value was not the None default, do nothing
        if value is not None:
            return value

        # iterate over the unit tests and create a TestGroup (and as a result, an IntegrationTest) for each
        test_groups: list[TestGroup] = []
        for unit_test in values["tests"]:
            test_group = TestGroup.derive_from_unit_test(unit_test, values["name"])
            test_groups.append(test_group)

        # now add each integration test to the list of tests
        for test_group in test_groups:
            values["tests"].append(test_group.integration_test)
        return test_groups


    def get_content_dependencies(self) -> list[SecurityContentObject]:
        return self.playbooks + self.baselines + self.macros + self.lookups

    @staticmethod
    def get_detections_from_filenames(
        detection_filenames: set[str],
        all_detections: list[Detection_Abstract]
    ) -> list[Detection_Abstract]:
        detection_filenames = set(str(pathlib.Path(filename).absolute()) for filename in detection_filenames)
        detection_dict = SecurityContentObject.create_filename_to_content_dict(all_detections)

        try:
            return [detection_dict[detection_filename] for detection_filename in detection_filenames]
        except Exception as e:
            raise Exception(f"Failed to find detection object for modified detection: {str(e)}")

    # @validator("type")
    # def type_valid(cls, v, values):
    #     if v.lower() not in [el.name.lower() for el in AnalyticsType]:
    #         raise ValueError("not valid analytics type: " + values["name"])
    #     return v

    @validator('how_to_implement', 'search', 'known_false_positives')
    def encode_error(cls, v, values, field):
        if not isinstance(v, str):
            if isinstance(v, dict) and field.name == "search":
                # This is a special case of the search field.  It can be a dict, containing
                # a sigma search, if we are running the converter. So we will not
                # validate the field further. Additional validation will be done
                # during conversion phase later on
                return v
            else:
                # No other fields should contain a non-str type:
                raise ValueError(
                    f"Error validating field '{field.name}'. Field MUST be be a string, not type '{type(v)}' "
                )

        return SecurityContentObject.free_text_field_valid(cls, v, values, field)

    @validator('enabled_by_default')
    def only_enabled_if_production_status(cls,v,values):
        '''
        A detection can ONLY be enabled by default if it is a PRODUCTION detection.
        If not (for example, it is EXPERIMENTAL or DEPRECATED) then we will throw an exception.
        Similarly, a detection MUST be schedulable, meaning that it must be Anomaly, Correleation, or TTP.
        We will not allow Hunting searches to be enabled by default.
        '''
        if v == False:
            return v

        status = DetectionStatus(values.get("status"))
        searchType = AnalyticsType(values.get("type"))
        errors = []
        if status != DetectionStatus.production:
            errors.append(f"status is '{status.name}'. Detections that are enabled by default MUST be '{DetectionStatus.production.value}'")
            
        if searchType not in [AnalyticsType.Anomaly, AnalyticsType.Correlation, AnalyticsType.TTP]:            
            errors.append(f"type is '{searchType.value}'. Detections that are enabled by default MUST be one of the following types: {[AnalyticsType.Anomaly.value, AnalyticsType.Correlation.value, AnalyticsType.TTP.value]}")
        if len(errors) > 0:
            error_message = "\n  - ".join(errors)
            raise ValueError(f"Detection is 'enabled_by_default: true' however \n  - {error_message}")
        
        return v
        

    @validator("status")
    def validation_for_ba_only(cls, v, values):
        # Ensure that only a BA detection can have status: validation
        p = pathlib.Path(values['file_path'])
        if v == DetectionStatus.validation.value:
            if p.name.startswith("ssa___"):
                pass
            else:
                raise ValueError(
                    f"The following is NOT an ssa_ detection, but has 'status: {v}' which may ONLY be used for "
                    f"ssa_ detections: {values['file_path']}"
                )

        return v

    # @root_validator
    # def search_validation(cls, values):
    #     if 'ssa_' not in values['file_path']:
    #         if not '_filter' in values['search']:
    #             raise ValueError('filter macro missing in: ' + values["name"])
    #         if any(x in values['search'] for x in ['eventtype=', 'sourcetype=', ' source=', 'index=']):
    #             if not 'index=_internal' in values['search']:
    #                 raise ValueError('Use source macro instead of eventtype, sourcetype, source or index in detection: ' + values["name"])
    #     return values

    # disable it because of performance reasons
    # @validator('references')
    # def references_check(cls, v, values):
    #     return LinkValidator.check_references(v, values["name"])
    #     return v

    @validator("search")
    def search_obsersables_exist_validate(cls, v, values):
        if type(v) is str:
            tags: DetectionTags = values.get("tags")
            if tags is None:
                raise ValueError("Unable to parse Detection Tags.  Please resolve Detection Tags errors")

            observable_fields = [ob.name.lower() for ob in tags.observable]

            # All $field$ fields from the message must appear in the search
            field_match_regex = r"\$([^\s.]*)\$"

            message_fields = [
                match.replace("$", "").lower() for match in re.findall(field_match_regex, tags.message.lower())
            ]
            missing_fields = set([field for field in observable_fields if field not in v.lower()])

            error_messages = []
            if len(missing_fields) > 0:
                error_messages.append(
                    f"The following fields are declared as observables, but do not exist in the search: "
                    f"{missing_fields}"
                )

            missing_fields = set([field for field in message_fields if field not in v.lower()])
            if len(missing_fields) > 0:
                error_messages.append(
                    f"The following fields are used as fields in the message, but do not exist in the search: "
                    f"{missing_fields}"
                )

            if len(error_messages) > 0 and values.get("status") == DetectionStatus.production.value:
                msg = "\n\t".join(error_messages)
                raise (ValueError(msg))

        # Found everything
        return v

    @validator("tests", always=True)
    def tests_validate(cls, v, values):
        # TODO (cmcginley): Fix detection_abstract.tests_validate so that it surfaces validation errors
        #   (e.g. a lack of tests) to the final results, instead of just showing a failed detection w/
        #   no tests (maybe have a message propagated at the detection level? do a separate coverage
        #   check as part of validation?):
    
    
        #Only production analytics require tests
        if values.get("status","") != DetectionStatus.production.value:
            return v
        
        # All types EXCEPT Correlation MUST have test(s). Any other type, including newly defined types, requires them.
        # Accordingly, we do not need to do additional checks if the type is Correlation
        if values.get("type","") in set([AnalyticsType.Correlation.value]):
            return v
        
            
        # Ensure that there is at least 1 test        
        if len(v) == 0:
            if values.get("tags",None) and values.get("tags").manual_test is not None:
                # Detections that are manual_test MAY have detections, but it is not required.  If they
                # do not have one, then create one which will be a placeholder.
                # Note that this fake UnitTest (and by extension, Integration Test) will NOT be generated
                # if there ARE test(s) defined for a Detection.
                placeholder_test = UnitTest(name="PLACEHOLDER FOR DETECTION TAGGED MANUAL_TEST WITH NO TESTS SPECIFIED IN YML FILE", attack_data=[])
                return [placeholder_test]
            
            else:
                raise ValueError("At least one test is REQUIRED for production detection: " + values.get("name", "NO NAME FOUND"))


        #No issues - at least one test provided for production type requiring testing
        return v

    @validator("datamodel")
    def datamodel_valid(cls, v, values):
        for datamodel in v:
            if datamodel not in [el.name for el in DataModel]:
                raise ValueError("not valid data model: " + values["name"])
        return v

    def all_tests_successful(self) -> bool:
        """
        Checks that all tests in the detection succeeded. If no tests are defined, consider that a
        failure; if any test fails (FAIL, ERROR), consider that a failure; if any test has
        no result or no status, consider that a failure. If all tests succeed (PASS, SKIP), consider
        the detection a success
        :returns: bool where True indicates all tests succeeded (they existed, complete and were
            PASS/SKIP)
        """
        # If no tests are defined, we consider it a failure for the detection
        if len(self.tests) == 0:
            return False

        # Iterate over tests
        for test in self.tests:
            # Check that test.result is not None
            if test.result is not None:
                # Check status is set (complete)
                if test.result.complete:
                    # Check for failure (FAIL, ERROR)
                    if test.result.failed:
                        return False
                else:
                    # If no stauts, return False
                    return False
            else:
                # If no result, return False
                return False

        # If all tests are successful (PASS/SKIP), return True
        return True

    def get_summary(
        self,
        detection_fields: list[str] = ["name", "search"],
        test_result_fields: list[str] = ["success", "message", "exception", "status", "duration", "wait_duration"],
        test_job_fields: list[str] = ["resultCount", "runDuration"],
    ) -> dict:
        """
        Aggregates a dictionary summarizing the detection model, including all test results
        :param detection_fields: the fields of the top level detection to gather
        :param test_result_fields: the fields of the test result(s) to gather
        :param test_job_fields: the fields of the test result(s) job content to gather
        :returns: a dict summary
        """
        # Init the summary dict
        summary_dict = {}

        # Grab the top level detection fields
        for field in detection_fields:
            summary_dict[field] = getattr(self, field)

        # Set success based on whether all tests passed
        summary_dict["success"] = self.all_tests_successful()

        # Aggregate test results
        summary_dict["tests"] = []
        for test in self.tests:
            # Initialize the dict as a mapping of strings to str/bool
            result: dict[str, Union[str, bool]] = {
                "name": test.name,
                "test_type": test.test_type.value
            }

            # If result is not None, get a summary of the test result w/ the requested fields
            if test.result is not None:
                result.update(
                    test.result.get_summary_dict(
                        model_fields=test_result_fields,
                        job_fields=test_job_fields,
                    )
                )
            else:
                # If no test result, consider it a failure
                result["success"] = False
                result["message"] = "NO RESULT - Test not run"

            # Add the result to our list
            summary_dict["tests"].append(result)

        # Return the summary
        return summary_dict
