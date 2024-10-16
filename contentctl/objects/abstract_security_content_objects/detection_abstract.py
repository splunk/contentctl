from __future__ import annotations
from typing import TYPE_CHECKING, Union, Optional, List, Any, Annotated
import re
import pathlib
from enum import Enum

from pydantic import (
    field_validator,
    model_validator,
    ValidationInfo,
    Field,
    computed_field,
    model_serializer,
    ConfigDict,
    FilePath
)

from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    from contentctl.objects.baseline import Baseline
    from contentctl.objects.config import CustomApp
    
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.enums import NistCategory

from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.deployment import Deployment
from contentctl.objects.unit_test import UnitTest
from contentctl.objects.manual_test import ManualTest
from contentctl.objects.test_group import TestGroup
from contentctl.objects.integration_test import IntegrationTest
from contentctl.objects.data_source import DataSource
from contentctl.objects.base_test_result import TestResultStatus
from contentctl.objects.drilldown import Drilldown, DRILLDOWN_SEARCH_PLACEHOLDER
from contentctl.objects.enums import ProvidingTechnology
from contentctl.enrichments.cve_enrichment import CveEnrichmentObj
import datetime
from contentctl.objects.constants import (
    ES_MAX_STANZA_LENGTH,
    ES_SEARCH_STANZA_NAME_FORMAT_AFTER_CLONING_IN_PRODUCT_TEMPLATE,
    CONTENTCTL_MAX_SEARCH_NAME_LENGTH,
    CONTENTCTL_DETECTION_STANZA_NAME_FORMAT_TEMPLATE
)

MISSING_SOURCES: set[str] = set()

# Those AnalyticsTypes that we do not test via contentctl
SKIPPED_ANALYTICS_TYPES: set[str] = {
    AnalyticsType.Correlation.value
}


# TODO (#266): disable the use_enum_values configuration
class Detection_Abstract(SecurityContentObject):
    model_config = ConfigDict(use_enum_values=True)
    name:str = Field(...,max_length=CONTENTCTL_MAX_SEARCH_NAME_LENGTH)
    #contentType: SecurityContentType = SecurityContentType.detections
    type: AnalyticsType = Field(...)
    status: DetectionStatus = Field(...)
    data_source: list[str] = []
    tags: DetectionTags = Field(...)
    search: str = Field(...)
    how_to_implement: str = Field(..., min_length=4)
    known_false_positives: str = Field(..., min_length=4)
    explanation: None | str = Field(
        default=None,
        exclude=True, #Don't serialize this value when dumping the object
        description="Provide an explanation to be included "
        "in the 'Explanation' field of the Detection in "
        "the Use Case Library. If this field is not "
        "defined in the YML, it will default to the "
        "value of the 'description' field when " 
        "serialized in analyticstories_detections.j2",
    )

    enabled_by_default: bool = False
    file_path: FilePath = Field(...)
    # For model construction to first attempt construction of the leftmost object.
    # From a file, this should be UnitTest. Note this is different than the
    # default mode, 'smart'
    # https://docs.pydantic.dev/latest/concepts/unions/#left-to-right-mode
    # https://github.com/pydantic/pydantic/issues/9101#issuecomment-2019032541
    tests: List[Annotated[Union[UnitTest, IntegrationTest, ManualTest], Field(union_mode='left_to_right')]] = []
    # A list of groups of tests, relying on the same data
    test_groups: list[TestGroup] = []

    data_source_objects: list[DataSource] = []
    drilldown_searches: list[Drilldown] = Field(default=[], description="A list of Drilldowns that should be included with this search")

    def get_conf_stanza_name(self, app:CustomApp)->str:
        stanza_name = CONTENTCTL_DETECTION_STANZA_NAME_FORMAT_TEMPLATE.format(app_label=app.label, detection_name=self.name)
        self.check_conf_stanza_max_length(stanza_name)
        return stanza_name
    

    def get_action_dot_correlationsearch_dot_label(self, app:CustomApp, max_stanza_length:int=ES_MAX_STANZA_LENGTH)->str:
        stanza_name = self.get_conf_stanza_name(app)
        stanza_name_after_saving_in_es = ES_SEARCH_STANZA_NAME_FORMAT_AFTER_CLONING_IN_PRODUCT_TEMPLATE.format(
            security_domain_value = self.tags.security_domain.value, 
            search_name = stanza_name
            )
        
    
        if len(stanza_name_after_saving_in_es) > max_stanza_length:
            raise ValueError(f"label may only be {max_stanza_length} characters to allow updating in-product, "
                             f"but stanza was actually {len(stanza_name_after_saving_in_es)} characters: '{stanza_name_after_saving_in_es}' ")
        
        return stanza_name    

    @field_validator("search", mode="before")
    @classmethod
    def validate_presence_of_filter_macro(cls, value:str, info:ValidationInfo)->str:
        """
        Validates that, if required to be present, the filter macro is present with the proper name.
        The filter macro MUST be derived from the name of the detection


        Args:
            value (str): The SPL search. It must be an SPL-formatted string.
            info (ValidationInfo): The validation info can contain a number of different objects.
                Today it only contains the director.

        Returns:
            str: The search, as an SPL formatted string.
        """
        
        # Otherwise, the search is SPL.

        # In the future, we will may add support that makes the inclusion of the
        # filter macro optional or automatically generates it for searches that
        # do not have it. For now, continue to require that all searches have a filter macro.
        FORCE_FILTER_MACRO = True
        if not FORCE_FILTER_MACRO:
            return value

        # Get the required macro name, which is derived from the search name.
        # Note that a separate validation ensures that the file name matches the content name
        name: Union[str, None] = info.data.get("name", None)
        if name is None:
            # The search was sigma formatted (or failed other validation and was None), so we will
            # not validate macros in it
            raise ValueError(
                "Cannot validate filter macro, field 'name' (which is required to validate the "
                "macro) was missing from the detection YML."
            )

        # Get the file name without the extension. Note this is not a full path!
        file_name = pathlib.Path(cls.contentNameToFileName(name)).stem
        file_name_with_filter = f"`{file_name}_filter`"

        if file_name_with_filter not in value:
            raise ValueError(
                f"Detection does not contain the EXACT filter macro {file_name_with_filter}. "
                "This filter macro MUST be present in the search. It usually placed at the end "
                "of the search and is useful for environment-specific filtering of False Positive or noisy results."
            )

        return value

    def adjust_tests_and_groups(self) -> None:
        """
        Converts UnitTest to ManualTest as needed, B=builds the `test_groups` field, constructing
        the model from the list of unit tests. Also, preemptively skips all manual tests, as well as
        tests for experimental/deprecated detections and Correlation type detections.
        """
        
        # Since ManualTest and UnitTest are not differentiable without looking at the manual_test
        # tag, Pydantic builds all tests as UnitTest objects. If we see the manual_test flag, we
        # convert these to ManualTest
        tmp: list[UnitTest | IntegrationTest | ManualTest] = []
        if self.tags.manual_test is not None:
            for test in self.tests:
                if not isinstance(test, UnitTest):
                    raise ValueError(
                        "At this point of intialization, tests should only be UnitTest objects, "
                        f"but encountered a {type(test)}."
                    )
                # Create the manual test and skip it upon creation (cannot test via contentctl)
                manual_test = ManualTest(
                    name=test.name,
                    attack_data=test.attack_data
                )
                tmp.append(manual_test)
            self.tests = tmp

        # iterate over the tests and create a TestGroup (and as a result, an IntegrationTest) for
        # each unit test
        self.test_groups = []
        for test in self.tests:
            # We only derive TestGroups from UnitTests (ManualTest is ignored and IntegrationTests
            # have not been created yet)
            if isinstance(test, UnitTest):
                test_group = TestGroup.derive_from_unit_test(test, self.name)
                self.test_groups.append(test_group)

        # now add each integration test to the list of tests
        for test_group in self.test_groups:
            self.tests.append(test_group.integration_test)

        # Skip all manual tests
        self.skip_manual_tests()

        # NOTE: we ignore the type error around self.status because we are using Pydantic's
        # use_enum_values configuration
        # https://docs.pydantic.dev/latest/api/config/#pydantic.config.ConfigDict.populate_by_name

        # Skip tests for non-production detections
        if self.status != DetectionStatus.production.value:                                         # type: ignore
            self.skip_all_tests(f"TEST SKIPPED: Detection is non-production ({self.status})")

        # Skip tests for detecton types like Correlation which are not supported via contentctl
        if self.type in SKIPPED_ANALYTICS_TYPES:
            self.skip_all_tests(
                f"TEST SKIPPED: Detection type {self.type} cannot be tested by contentctl"
            )

    @property
    def test_status(self) -> TestResultStatus | None:
        """
        Returns the collective status of the detections tests. If any test status has yet to be set,
        None is returned.If any test failed or errored, FAIL is returned. If all tests were skipped,
        SKIP is returned. If at least one test passed and the rest passed or skipped, PASS is
        returned.
        """
        # If the detection has no tests, we consider it to have been skipped (only non-production,
        # non-manual, non-correlation detections are allowed to have no tests defined)
        if len(self.tests) == 0:
            return TestResultStatus.SKIP

        passed = 0
        skipped = 0
        for test in self.tests:
            # If the result/status of any test has not yet been set, return None
            if test.result is None or test.result.status is None:
                return None
            elif test.result.status == TestResultStatus.ERROR or test.result.status == TestResultStatus.FAIL:
                # If any test failed or errored, return fail (we don't return the error state at
                # the aggregate detection level)
                return TestResultStatus.FAIL
            elif test.result.status == TestResultStatus.SKIP:
                skipped += 1
            elif test.result.status == TestResultStatus.PASS:
                passed += 1
            else:
                raise ValueError(
                    f"Undefined test status for test ({test.name}) in detection ({self.name})"
                )

        # If at least one of the tests passed and the rest passed or skipped, report pass
        if passed > 0 and (passed + skipped) == len(self.tests):
            return TestResultStatus.PASS
        elif skipped == len(self.tests):
            # If all tests skipped, return skip
            return TestResultStatus.SKIP

        raise ValueError(f"Undefined overall test status for detection: {self.name}")

    @computed_field
    @property
    def datamodel(self) -> List[DataModel]:
        return [dm for dm in DataModel if dm.value in self.search]
        
            
    

    @computed_field
    @property
    def source(self) -> str:
        return self.file_path.absolute().parent.name
        

    deployment: Deployment = Field({})

    @computed_field
    @property
    def annotations(self) -> dict[str, Union[List[str], int, str]]:

        annotations_dict: dict[str, str | list[str] | int] = {}
        annotations_dict["analytic_story"] = [story.name for story in self.tags.analytic_story]
        annotations_dict["confidence"] = self.tags.confidence
        if len(self.tags.cve or []) > 0:
            annotations_dict["cve"] = self.tags.cve
        annotations_dict["impact"] = self.tags.impact
        annotations_dict["type"] = self.type
        annotations_dict["type_list"] = [self.type]
        # annotations_dict["version"] = self.version

        annotations_dict["data_source"] = self.data_source

        # The annotations object is a superset of the mappings object.
        # So start with the mapping object.
        annotations_dict.update(self.mappings)

        # Make sure that the results are sorted for readability/easier diffs
        return dict(sorted(annotations_dict.items(), key=lambda item: item[0]))

    # playbooks: list[Playbook] = []

    baselines: list[Baseline] = Field([], validate_default=True)

    @computed_field
    @property
    def mappings(self) -> dict[str, List[str]]:
        mappings: dict[str, Any] = {}
        if len(self.tags.cis20) > 0:
            mappings["cis20"] = [tag.value for tag in self.tags.cis20]
        if len(self.tags.kill_chain_phases) > 0:
            mappings['kill_chain_phases'] = [phase.value for phase in self.tags.kill_chain_phases]
        if len(self.tags.mitre_attack_id) > 0:
            mappings['mitre_attack'] = self.tags.mitre_attack_id
        if len(self.tags.nist) > 0:
            mappings['nist'] = [category.value for category in self.tags.nist]

        # No need to sort the dict! It has been constructed in-order.
        # However, if this logic is changed, then consider reordering or
        # adding the sort back!
        # return dict(sorted(mappings.items(), key=lambda item: item[0]))
        return mappings

    macros: list[Macro] = Field([], validate_default=True)
    lookups: list[Lookup] = Field([], validate_default=True)

    cve_enrichment: list[CveEnrichmentObj] = Field([], validate_default=True)

    def cve_enrichment_func(self, __context: Any):
        if len(self.cve_enrichment) > 0:
            raise ValueError(f"Error, field 'cve_enrichment' should be empty and "
                             f"dynamically populated at runtime. Instead, this field contained: {self.cve_enrichment}")

        output_dto: Union[DirectorOutputDto, None] = __context.get("output_dto", None)
        if output_dto is None:
            raise ValueError("Context not provided to detection model post validator")

        enriched_cves: list[CveEnrichmentObj] = []

        for cve_id in self.tags.cve:
            try:
                enriched_cves.append(output_dto.cve_enrichment.enrich_cve(cve_id, raise_exception_on_failure=False))
            except Exception as e:
                raise ValueError(f"{e}")
        self.cve_enrichment = enriched_cves
        return self

    splunk_app_enrichment: Optional[List[dict]] = None

    @computed_field
    @property
    def nes_fields(self) -> Optional[str]:
        if self.deployment.alert_action.notable is not None:
            return ','.join(self.deployment.alert_action.notable.nes_fields)
        else:
            return None

    @computed_field
    @property
    def providing_technologies(self) -> List[ProvidingTechnology]:
        return ProvidingTechnology.getProvidingTechFromSearch(self.search)

    # TODO (#247): Refactor the risk property of detection_abstract
    @computed_field
    @property
    def risk(self) -> list[dict[str, Any]]:
        risk_objects: list[dict[str, str | int]] = []
        # TODO (#246): "User Name" type should map to a "user" risk object and not "other"
        risk_object_user_types = {'user', 'username', 'email address'}
        risk_object_system_types = {'device', 'endpoint', 'hostname', 'ip address'}
        process_threat_object_types = {'process name', 'process'}
        file_threat_object_types = {'file name', 'file', 'file hash'}
        url_threat_object_types = {'url string', 'url'}
        ip_threat_object_types = {'ip address'}

        for entity in self.tags.observable:
            risk_object: dict[str, str | int] = dict()
            if 'Victim' in entity.role and entity.type.lower() in risk_object_user_types:
                risk_object['risk_object_type'] = 'user'
                risk_object['risk_object_field'] = entity.name
                risk_object['risk_score'] = self.tags.risk_score
                risk_objects.append(risk_object)

            elif 'Victim' in entity.role and entity.type.lower() in risk_object_system_types:
                risk_object['risk_object_type'] = 'system'
                risk_object['risk_object_field'] = entity.name
                risk_object['risk_score'] = self.tags.risk_score
                risk_objects.append(risk_object)

            elif 'Attacker' in entity.role and entity.type.lower() in process_threat_object_types:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = "process"
                risk_objects.append(risk_object)

            elif 'Attacker' in entity.role and entity.type.lower() in file_threat_object_types:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = "file_name"
                risk_objects.append(risk_object)

            elif 'Attacker' in entity.role and entity.type.lower() in ip_threat_object_types:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = "ip_address"
                risk_objects.append(risk_object)

            elif 'Attacker' in entity.role and entity.type.lower() in url_threat_object_types:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = "url"
                risk_objects.append(risk_object)
            
            elif 'Attacker' in entity.role:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = entity.type.lower()
                risk_objects.append(risk_object)

            else:
                risk_object['risk_object_type'] = 'other'
                risk_object['risk_object_field'] = entity.name
                risk_object['risk_score'] = self.tags.risk_score
                risk_objects.append(risk_object)
                continue

        return risk_objects

    @computed_field
    @property
    def metadata(self) -> dict[str, str|float]:
        # NOTE: we ignore the type error around self.status because we are using Pydantic's
        # use_enum_values configuration
        # https://docs.pydantic.dev/latest/api/config/#pydantic.config.ConfigDict.populate_by_name

        # NOTE: The `inspect` action is HIGHLY sensitive to the structure of the metadata line in
        # the detection stanza in savedsearches.conf. Additive operations (e.g. a new field in the
        # dict below) should not have any impact, but renaming or removing any of these fields will
        # break the `inspect` action.
        return {
            'detection_id': str(self.id),
            'deprecated': '1' if self.status == DetectionStatus.deprecated.value else '0',          # type: ignore
            'detection_version': str(self.version),
            'publish_time': datetime.datetime(self.date.year,self.date.month,self.date.day,0,0,0,0,tzinfo=datetime.timezone.utc).timestamp()
        }

    @model_serializer
    def serialize_model(self):
        # Call serializer for parent
        super_fields = super().serialize_model()

        # All fields custom to this model
        model = {
            "tags": self.tags.model_dump(),
            "type": self.type,
            "search": self.search,
            "how_to_implement": self.how_to_implement,
            "known_false_positives": self.known_false_positives,
            "datamodel": self.datamodel,
            "source": self.source,
            "nes_fields": self.nes_fields,
        }

        # Only a subset of macro fields are required:
        all_macros: list[dict[str, str | list[str]]] = []
        for macro in self.macros:
            macro_dump: dict[str, str | list[str]] = {
                "name": macro.name,
                "definition": macro.definition,
                "description": macro.description
            }
            if len(macro.arguments) > 0:
                macro_dump['arguments'] = macro.arguments

            all_macros.append(macro_dump)
        model['macros'] = all_macros                                                                # type: ignore

        all_lookups: list[dict[str, str | int | None]] = []
        for lookup in self.lookups:
            if lookup.collection is not None:
                all_lookups.append(
                    {
                        "name": lookup.name,
                        "description": lookup.description,
                        "collection": lookup.collection,
                        "case_sensitive_match": None,
                        "fields_list": lookup.fields_list
                    }
                )
            elif lookup.filename is not None:
                all_lookups.append(
                    {
                        "name": lookup.name,
                        "description": lookup.description,
                        "filename": lookup.filename.name,
                        "default_match": "true" if lookup.default_match else "false",
                        "case_sensitive_match": "true" if lookup.case_sensitive_match else "false",
                        "match_type": lookup.match_type,
                        "min_matches": lookup.min_matches,
                        "fields_list": lookup.fields_list
                    }
                )
        model['lookups'] = all_lookups                                                              # type: ignore

        # Combine fields from this model with fields from parent
        super_fields.update(model)                                                                  # type: ignore

        # return the model
        return super_fields

    def model_post_init(self, __context: Any) -> None:
        super().model_post_init(__context)
        director: Optional[DirectorOutputDto] = __context.get("output_dto", None)

        # Ensure that all baselines link to this detection
        for baseline in self.baselines:
            new_detections: list[Detection_Abstract | str] = []
            replaced = False
            for d in baseline.tags.detections:
                if isinstance(d, str) and self.name == d:
                    new_detections.append(self)
                    replaced = True
                else:
                    new_detections.append(d)
            if replaced is False:
                raise ValueError(
                    f"Error, failed to replace detection reference in Baseline '{baseline.name}' "
                    f"to detection '{self.name}'"
                )
            baseline.tags.detections = new_detections

        # Data source may be defined 1 on each line, OR they may be defined as
        # SOUCE_1 AND ANOTHERSOURCE AND A_THIRD_SOURCE
        # if more than 1 data source is required for a detection (for example, because it includes a join)
        # Parse and update the list to resolve individual names and remove potential duplicates
        updated_data_source_names: set[str] = set()

        for ds in self.data_source:
            split_data_sources = {d.strip() for d in ds.split('AND')}
            updated_data_source_names.update(split_data_sources)

        sources = sorted(list(updated_data_source_names))

        matched_data_sources: list[DataSource] = []
        missing_sources: list[str] = []
        for source in sources:
            try:
                matched_data_sources += DataSource.mapNamesToSecurityContentObjects([source], director)
            except Exception:
                # We gobble this up and add it to a global set so that we
                # can print it ONCE at the end of the build of datasources.
                # This will be removed later as per the note below
                MISSING_SOURCES.add(source)

        if len(missing_sources) > 0:
            # This will be changed to ValueError when we have a complete list of data sources
            print(
                "WARNING: The following exception occurred when mapping the data_source field to "
                f"DataSource objects:{missing_sources}"
            )

        self.data_source_objects = matched_data_sources

        for story in self.tags.analytic_story:
            story.detections.append(self)     

        self.cve_enrichment_func(__context)

        # Derive TestGroups and IntegrationTests, adjust for ManualTests, skip as needed
        self.adjust_tests_and_groups()

        # Ensure that if there is at least 1 drilldown, at least
        # 1 of the drilldowns contains the string Drilldown.SEARCH_PLACEHOLDER.
        # This is presently a requirement when 1 or more drilldowns are added to a detection.
        # Note that this is only required for production searches that are not hunting
            
        if self.type == AnalyticsType.Hunting.value or self.status != DetectionStatus.production.value:
            #No additional check need to happen on the potential drilldowns.
            pass
        else:
            found_placeholder = False
            if len(self.drilldown_searches) < 2:
                raise ValueError(f"This detection is required to have 2 drilldown_searches, but only has [{len(self.drilldown_searches)}]")
            for drilldown in self.drilldown_searches:
                if DRILLDOWN_SEARCH_PLACEHOLDER in drilldown.search:
                    found_placeholder = True
            if not found_placeholder:
                raise ValueError("Detection has one or more drilldown_searches, but none of them "
                                 f"contained '{DRILLDOWN_SEARCH_PLACEHOLDER}. This is a requirement "
                                 "if drilldown_searches are defined.'")
            
        # Update the search fields with the original search, if required
        for drilldown in self.drilldown_searches:
            drilldown.perform_search_substitutions(self)

        #For experimental purposes, add the default drilldowns
        #self.drilldown_searches.extend(Drilldown.constructDrilldownsFromDetection(self))

    @property
    def drilldowns_in_JSON(self) -> list[dict[str,str]]:
        """This function is required for proper JSON 
        serializiation of drilldowns to occur in savedsearches.conf.
        It returns the list[Drilldown] as a list[dict].
        Without this function, the jinja template is unable
        to convert list[Drilldown] to JSON

        Returns:
            list[dict[str,str]]: List of Drilldowns dumped to dict format
        """        
        return [drilldown.model_dump() for drilldown in self.drilldown_searches]

    @field_validator('lookups', mode="before")
    @classmethod
    def getDetectionLookups(cls, v:list[str], info:ValidationInfo) -> list[Lookup]:
        director:DirectorOutputDto = info.context.get("output_dto",None)
        
        search:Union[str,None] = info.data.get("search",None)
        if search is None:
            raise ValueError("Search was None - is this file missing the search field?")
        
        lookups = Lookup.get_lookups(search, director)
        return lookups

    @field_validator('baselines', mode="before")
    @classmethod
    def mapDetectionNamesToBaselineObjects(cls, v: list[str], info: ValidationInfo) -> List[Baseline]:
        if len(v) > 0:
            raise ValueError(
                "Error, baselines are constructed automatically at runtime.  Please do not include this field."
            )

        name: Union[str, None] = info.data.get("name", None)
        if name is None:
            raise ValueError("Error, cannot get Baselines because the Detection does not have a 'name' defined.")

        if info.context is None:
            raise ValueError("ValidationInfo.context unexpectedly null")

        director: DirectorOutputDto = info.context.get("output_dto", None)
        baselines: List[Baseline] = []
        for baseline in director.baselines:
            # This matching is a bit strange, because baseline.tags.detections starts as a list of strings, but
            # is eventually updated to a list of Detections as we construct all of the detection objects.
            detection_names = [
                detection_name for detection_name in baseline.tags.detections if isinstance(detection_name, str)
            ]
            if name in detection_names:
                baselines.append(baseline)

        return baselines

    @field_validator('macros', mode="before")
    @classmethod
    def getDetectionMacros(cls, v: list[str], info: ValidationInfo) -> list[Macro]:
        if info.context is None:
            raise ValueError("ValidationInfo.context unexpectedly null")

        director: DirectorOutputDto = info.context.get("output_dto", None)

        search: str | None = info.data.get("search", None)
        if search is None:
            raise ValueError("Search was None - is this file missing the search field?")

        search_name: Union[str, Any] = info.data.get("name", None)
        message = f"Expected 'search_name' to be a string, instead it was [{type(search_name)}]"
        assert isinstance(search_name, str), message

        filter_macro_name = search_name.replace(' ', '_')\
            .replace('-', '_')\
            .replace('.', '_')\
            .replace('/', '_')\
            .lower()\
            + '_filter'
        try:
            filter_macro = Macro.mapNamesToSecurityContentObjects([filter_macro_name], director)[0]
        except Exception:
            # Filter macro did not exist, so create one at runtime
            filter_macro = Macro.model_validate(
                {
                    "name": filter_macro_name,
                    "definition": 'search *',
                    "description": 'Update this macro to limit the output results to filter out false positives.'
                }
            )
            director.addContentToDictMappings(filter_macro)

        macros_from_search = Macro.get_macros(search, director)

        return macros_from_search

    def get_content_dependencies(self) -> list[SecurityContentObject]:
        # Do this separately to satisfy type checker
        objects: list[SecurityContentObject] = []
        objects += self.macros
        objects += self.lookups
        objects += self.data_source_objects
        return objects

    @field_validator("deployment", mode="before")
    def getDeployment(cls, v: Any, info: ValidationInfo) -> Deployment:
        return Deployment.getDeployment(v, info)

    @field_validator("enabled_by_default", mode="before")
    def only_enabled_if_production_status(cls, v: Any, info: ValidationInfo) -> bool:
        '''
        A detection can ONLY be enabled by default if it is a PRODUCTION detection.
        If not (for example, it is EXPERIMENTAL or DEPRECATED) then we will throw an exception.
        Similarly, a detection MUST be schedulable, meaning that it must be Anomaly, Correleation, or TTP.
        We will not allow Hunting searches to be enabled by default.
        '''
        if v is False:
            return v

        status = DetectionStatus(info.data.get("status"))
        searchType = AnalyticsType(info.data.get("type"))
        errors: list[str] = []
        if status != DetectionStatus.production:
            errors.append(
                f"status is '{status.name}'. Detections that are enabled by default MUST be "
                f"'{DetectionStatus.production.value}'"
                )

        if searchType not in [AnalyticsType.Anomaly, AnalyticsType.Correlation, AnalyticsType.TTP]:
            errors.append(
                f"type is '{searchType.value}'. Detections that are enabled by default MUST be one"
                " of the following types: "
                f"{[AnalyticsType.Anomaly.value, AnalyticsType.Correlation.value, AnalyticsType.TTP.value]}")
        if len(errors) > 0:
            error_message = "\n  - ".join(errors)
            raise ValueError(f"Detection is 'enabled_by_default: true' however \n  - {error_message}")

        return v

    @model_validator(mode="after")
    def addTags_nist(self):
        if self.type == AnalyticsType.TTP.value:
            self.tags.nist = [NistCategory.DE_CM]
        else:
            self.tags.nist = [NistCategory.DE_AE]
        return self
        

    @model_validator(mode="after")
    def ensureThrottlingFieldsExist(self):
        '''
        For throttling to work properly, the fields to throttle on MUST
        exist in the search itself.  If not, then we cannot apply the throttling
        '''
        if self.tags.throttling is None:
            # No throttling configured for this detection
            return self

        missing_fields:list[str] = [field for field in self.tags.throttling.fields if field not in self.search]
        if len(missing_fields) > 0:
            raise ValueError(f"The following throttle fields were missing from the search: {missing_fields}")

        else:
            # All throttling fields present in search
            return self
            


    @model_validator(mode="after")
    def ensureProperObservablesExist(self):
        """
        If a detections is PRODUCTION and either TTP or ANOMALY, then it MUST have an Observable with the VICTIM role.

        Returns:
            self: Returns itself if the valdiation passes
        """
        # NOTE: we ignore the type error around self.status because we are using Pydantic's
        # use_enum_values configuration
        # https://docs.pydantic.dev/latest/api/config/#pydantic.config.ConfigDict.populate_by_name
        if self.status not in [DetectionStatus.production.value]:                                   # type: ignore
            # Only perform this validation on production detections
            return self

        if self.type not in [AnalyticsType.TTP.value, AnalyticsType.Anomaly.value]:
            # Only perform this validation on TTP and Anomaly detections
            return self

        # Detection is required to have a victim
        roles: list[str] = []
        for observable in self.tags.observable:
            roles.extend(observable.role)

        if roles.count("Victim") == 0:
            raise ValueError(
                "Error, there must be AT LEAST 1 Observable with the role 'Victim' declared in "
                "Detection.tags.observables. However, none were found."
            )

        # Exactly one victim was found
        return self

    @model_validator(mode="after")
    def search_observables_exist_validate(self):
        observable_fields = [ob.name.lower() for ob in self.tags.observable]

        # All $field$ fields from the message must appear in the search
        field_match_regex = r"\$([^\s.]*)\$"

        missing_fields: set[str]
        if self.tags.message:
            matches = re.findall(field_match_regex, self.tags.message.lower())
            message_fields = [match.replace("$", "").lower() for match in matches]
            missing_fields = set([field for field in observable_fields if field not in self.search.lower()])
        else:
            message_fields = []
            missing_fields = set()

        error_messages: list[str] = []
        if len(missing_fields) > 0:
            error_messages.append(
                "The following fields are declared as observables, but do not exist in the "
                f"search: {missing_fields}"
            )

        missing_fields = set([field for field in message_fields if field not in self.search.lower()])
        if len(missing_fields) > 0:
            error_messages.append(
                "The following fields are used as fields in the message, but do not exist in "
                f"the search: {missing_fields}"
            )

        # NOTE: we ignore the type error around self.status because we are using Pydantic's
        # use_enum_values configuration
        # https://docs.pydantic.dev/latest/api/config/#pydantic.config.ConfigDict.populate_by_name
        if len(error_messages) > 0 and self.status == DetectionStatus.production.value:         # type: ignore
            msg = (
                "Use of fields in observables/messages that do not appear in search:\n\t- "
                "\n\t- ".join(error_messages)
            )
            raise ValueError(msg)

        # Found everything
        return self

    @field_validator("tests", mode="before")
    def ensure_yml_test_is_unittest(cls, v:list[dict]):
        """The typing for the tests field allows it to be one of
        a number of different types of tests. However, ONLY
        UnitTest should be allowed to be defined in the YML
        file.  If part of the UnitTest defined in the YML
        is incorrect, such as the attack_data file, then
        it will FAIL to be instantiated as a UnitTest and
        may instead be instantiated as a different type of
        test, such as IntegrationTest (since that requires
        less fields) which is incorrect. Ensure that any
        raw data read from the YML can actually construct
        a valid UnitTest and, if not, return errors right
        away instead of letting Pydantic try to construct
        it into a different type of test

        Args:
            v (list[dict]): list of dicts read from the yml. 
            Each one SHOULD be a valid UnitTest. If we cannot
            construct a valid unitTest from it, a ValueError should be raised

        Returns:
            _type_: The input of the function, assuming no 
            ValueError is raised.
        """        
        valueErrors:list[ValueError] = []
        for unitTest in v:
            #This raises a ValueError on a failed UnitTest.
            try:
                UnitTest.model_validate(unitTest)
            except ValueError as e:
                valueErrors.append(e)
        if len(valueErrors):
            raise ValueError(valueErrors)
        # All of these can be constructred as UnitTests with no
        # Exceptions, so let the normal flow continue
        return v
        

    @field_validator("tests")
    def tests_validate(
        cls,
        v: list[UnitTest | IntegrationTest | ManualTest],
        info: ValidationInfo
    ) -> list[UnitTest | IntegrationTest | ManualTest]:
        # Only production analytics require tests
        if info.data.get("status", "") != DetectionStatus.production.value:
            return v

        # All types EXCEPT Correlation MUST have test(s). Any other type, including newly defined
        # types, requires them. Accordingly, we do not need to do additional checks if the type is
        # Correlation
        if info.data.get("type", "") in SKIPPED_ANALYTICS_TYPES:
            return v

        # Manually tested detections are not required to have tests defined
        tags: DetectionTags | None = info.data.get("tags", None)
        if tags is not None and tags.manual_test is not None:
            return v

        # Ensure that there is at least 1 test
        if len(v) == 0:
            raise ValueError(
                "At least one test is REQUIRED for production detection: " + info.data.get("name", "NO NAME FOUND")
            )

        # No issues - at least one test provided for production type requiring testing
        return v

    def skip_all_tests(self, message: str = "TEST SKIPPED") -> None:
        """
        Given a message, skip all tests for this detection.
        :param message: the message to set in the test result
        """
        for test in self.tests:
            test.skip(message=message)

    def skip_manual_tests(self) -> None:
        """
        Skips all ManualTests, if the manual_test flag is set; also raises an error if any other
        test types are found for a manual_test detection
        """
        # Skip all ManualTest
        if self.tags.manual_test is not None:
            for test in self.tests:
                if isinstance(test, ManualTest):
                    test.skip(
                        message=(
                            "TEST SKIPPED (MANUAL): Detection marked as 'manual_test' with "
                            f"explanation: {self.tags.manual_test}"
                        )
                    )
                else:
                    raise ValueError(
                        "A detection with the manual_test flag should only have tests of type "
                        "ManualTest"
                    )

    def all_tests_successful(self) -> bool:
        """
        Checks that all tests in the detection succeeded. If no tests are defined, consider that a
        failure; if any test fails (FAIL, ERROR), consider that a failure; if any test has
        no result or no status, consider that a failure. If all tests succeed (PASS, SKIP), consider
        the detection a success
        :returns: bool where True indicates all tests succeeded (they existed, complete and were
            PASS/SKIP)
        """
        # If no tests are defined, we consider it a success for the detection (this detection was
        # skipped for testing). Note that the existence of at least one test is enforced by Pydantic
        # validation already, with a few specific exceptions
        if len(self.tests) == 0:
            return True

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
        detection_fields: list[str] = [
            "name", "type", "status", "test_status", "source", "data_source", "search", "file_path"
        ],
        detection_field_aliases: dict[str, str] = {
            "status": "production_status", "test_status": "status", "source": "source_category"
        },
        tags_fields: list[str] = ["manual_test"],
        test_result_fields: list[str] = ["success", "message", "exception", "status", "duration", "wait_duration"],
        test_job_fields: list[str] = ["resultCount", "runDuration"],
    ) -> dict[str, Any]:
        """
        Aggregates a dictionary summarizing the detection model, including all test results
        :param detection_fields: the fields of the top level detection to gather
        :param test_result_fields: the fields of the test result(s) to gather
        :param test_job_fields: the fields of the test result(s) job content to gather
        :returns: a dict summary
        """
        # Init the summary dict
        summary_dict: dict[str, Any] = {}

        # Grab the top level detection fields
        for field in detection_fields:
            value = getattr(self, field)

            # Enums and Path objects cannot be serialized directly, so we convert it to a string
            if isinstance(value, Enum) or isinstance(value, pathlib.Path):
                value = str(value)

            # Alias any fields as needed
            if field in detection_field_aliases:
                summary_dict[detection_field_aliases[field]] = value
            else:
                summary_dict[field] = value

        # Grab fields from the tags
        for field in tags_fields:
            summary_dict[field] = getattr(self.tags, field)

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
            summary_dict["tests"].append(result)                                                    # type: ignore

        # Return the summary

        return summary_dict
