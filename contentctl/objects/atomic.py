from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.config import validate

from contentctl.input.yml_reader import YmlReader
from pydantic import BaseModel, model_validator, ConfigDict, FilePath, UUID4
import dataclasses
from typing import List, Optional, Dict, Union, Self
import pathlib
from enum import StrEnum, auto
import uuid

class SupportedPlatform(StrEnum):        
    windows = auto()
    linux = auto()
    macos = auto()
    containers = auto()
    # Because the following fields contain special characters 
    # (which cannot be field names) we must specifiy them manually
    google_workspace = "google-workspace"
    iaas_gcp = "iaas:gcp"
    iaas_azure = "iaas:azure"
    iaas_aws = "iaas:aws"
    azure_ad = "azure-ad"
    office_365 = "office-365"
    


class InputArgumentType(StrEnum):
    string = auto()
    path = auto()
    url = auto()
    integer = auto()
    float = auto()
    # Cannot use auto() since the case sensitivity is important
    # These should likely be converted in the ART repo to use the same case
    # As the defined types above
    String = "String"
    Path = "Path"
    Url = "Url"

class AtomicExecutor(BaseModel):
    name: str
    elevation_required: Optional[bool] = False #Appears to be optional
    command: Optional[str] = None
    steps: Optional[str] = None
    cleanup_command: Optional[str] = None

    @model_validator(mode='after')
    def ensure_mutually_exclusive_fields(self)->Self:
        if self.command is not None and self.steps is not None:
            raise ValueError("command and steps cannot both be defined in the executor section.  Exactly one must be defined.")
        elif self.command is None and self.steps is None:
            raise ValueError("Neither command nor steps were defined in the executor section.  Exactly one must be defined.")
        return self
    


class InputArgument(BaseModel):
    model_config = ConfigDict(extra='forbid')
    description: str
    type: InputArgumentType
    default: Union[str,int,float,None] = None


class DependencyExecutorType(StrEnum):
    powershell = auto()
    sh = auto()
    bash = auto()
    command_prompt = auto()

class AtomicDependency(BaseModel):
    model_config = ConfigDict(extra='forbid')
    description: str
    prereq_command: str
    get_prereq_command: str

class AtomicTest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str
    auto_generated_guid: UUID4
    description: str
    supported_platforms: List[SupportedPlatform]
    executor: AtomicExecutor
    input_arguments: Optional[Dict[str,InputArgument]] = None
    dependencies: Optional[List[AtomicDependency]] = None
    dependency_executor_name: Optional[DependencyExecutorType] = None

    @staticmethod
    def AtomicTestWhenTestIsMissing(auto_generated_guid: UUID4) -> AtomicTest:
        return AtomicTest(name="Missing Atomic",
                          auto_generated_guid=auto_generated_guid,
                          description="This is a placeholder AtomicTest. Either the auto_generated_guid is incorrect or it there was an exception while parsing its AtomicFile.",
                          supported_platforms=[],
                          executor=AtomicExecutor(name="Placeholder Executor (failed to find auto_generated_guid)", 
                                                  command="Placeholder command (failed to find auto_generated_guid)"))    
    
    @classmethod
    def parseArtRepo(cls, repo_path:pathlib.Path)->dict[uuid.UUID, AtomicTest]:
        test_mapping: dict[uuid.UUID, AtomicTest] = {}
        atomics_path = repo_path/"atomics"
        if not atomics_path.is_dir():
            raise FileNotFoundError(f"WARNING: Atomic Red Team repo exists at {repo_path}, "
                                    f"but atomics directory does NOT exist at {atomics_path}. "
                                    "Was it deleted or renamed?")

        atomic_files:List[AtomicFile] = []
        error_messages:List[str] = []
        for obj_path in atomics_path.glob("**/T*.yaml"):
            try:
                atomic_files.append(cls.constructAtomicFile(obj_path))
            except Exception as e:
                error_messages.append(f"File [{obj_path}]\n{str(e)}")

        if len(error_messages) > 0:
            exceptions_string = '\n\n'.join(error_messages)
            print(f"WARNING: The following [{len(error_messages)}] ERRORS were generated when parsing the Atomic Red Team Repo.\n"
                   "Please raise an issue so that they can be fixed at https://github.com/redcanaryco/atomic-red-team/issues.\n"
                   "Note that this is only a warning and contentctl will ignore Atomics contained in these files.\n"
                  f"However, if you have written a detection that references them, 'contentctl build --enrichments' will fail:\n\n{exceptions_string}")
        
        # Now iterate over all the files, collect all the tests, and return the dict mapping
        redefined_guids:set[uuid.UUID] = set()
        for atomic_file in atomic_files:
            for atomic_test in atomic_file.atomic_tests:
                if atomic_test.auto_generated_guid in test_mapping:
                    redefined_guids.add(atomic_test.auto_generated_guid)
                else:
                    test_mapping[atomic_test.auto_generated_guid] = atomic_test
        if len(redefined_guids) > 0:
            guids_string = '\n\t'.join([str(guid) for guid in redefined_guids])
            raise Exception(f"The following [{len(redefined_guids)}] Atomic Test"
                            " auto_generated_guid(s) were defined more than once. "
                            f"auto_generated_guids MUST be unique:\n\t{guids_string}")

        print(f"Successfully parsed [{len(test_mapping)}] Atomic Red Team Tests!")
        return test_mapping
    
    @classmethod
    def constructAtomicFile(cls, file_path:pathlib.Path)->AtomicFile:
        yml_dict = YmlReader.load_file(file_path) 
        atomic_file = AtomicFile.model_validate(yml_dict)
        return atomic_file


class AtomicFile(BaseModel):
    model_config = ConfigDict(extra='forbid')
    file_path: FilePath
    attack_technique: str
    display_name: str
    atomic_tests: List[AtomicTest]


class AtomicEnrichment(BaseModel):
    data: dict[uuid.UUID,AtomicTest] = dataclasses.field(default_factory = dict)
    use_enrichment: bool = False

    @classmethod
    def getAtomicEnrichment(cls, config:validate)->AtomicEnrichment:
        enrichment = AtomicEnrichment(use_enrichment=config.enrichments)
        if config.enrichments:
            enrichment.data = AtomicTest.parseArtRepo(config.atomic_red_team_repo_path)

        return enrichment

    def getAtomic(self, atomic_guid: uuid.UUID)->AtomicTest:
        if self.use_enrichment:
            if atomic_guid in self.data:
                return self.data[atomic_guid]
            else:
                raise Exception(f"Atomic with GUID {atomic_guid} not found.")
        else:
            # If enrichment is not enabled, for the sake of compatability
            # return a stub test with no useful or meaningful information.
            return AtomicTest.AtomicTestWhenTestIsMissing(atomic_guid)

    

    

        
    