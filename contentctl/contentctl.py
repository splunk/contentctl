import traceback
import sys
import warnings
import pathlib
import tyro

from contentctl.actions.initialize import Initialize
from contentctl.objects.config import init, validate, build,  new, deploy_acs, test, test_servers, inspect, report, test_common, release_notes
from contentctl.actions.validate import Validate
from contentctl.actions.new_content import NewContent
from contentctl.actions.detection_testing.GitService import GitService
from contentctl.actions.build import (
     BuildInputDto,
     DirectorOutputDto,
     Build,
)
from contentctl.actions.test import Test
from contentctl.actions.test import TestInputDto
from contentctl.actions.reporting import ReportingInputDto, Reporting
from contentctl.actions.inspect import Inspect
from contentctl.input.yml_reader import YmlReader
from contentctl.actions.release_notes import ReleaseNotes

# def print_ascii_art():
#     print(
#         """
# Running Splunk Security Content Control Tool (contentctl) 
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢶⠛⡇⠀⠀⠀⠀⠀⠀⣠⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⣀⠼⠖⠛⠋⠉⠉⠓⠢⣴⡻⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠀⢀⡠⠔⠊⠁⠀⠀⠀⠀⠀⠀⣠⣤⣄⠻⠟⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⣠⠞⠁⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⢻⣿⣿⠀⢀⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⢸⡇⠀⠀⠀⡠⠊⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠀⠈⠁⠘⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⢸⡉⠓⠒⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢄⠀⠀⠀⠈⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠈⡇⠀⢠⠀⠀⠀⠀⠀⠀⠀⠈⡷⣄⠀⠀⢀⠈⠀⠀⠑⢄⠀⠑⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠹⡄⠘⡄⠀⠀⠀⠀⢀⡠⠊⠀⠙⠀⠀⠈⢣⠀⠀⠀⢀⠀⠀⠀⠉⠒⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀
# ⠀⠀⠉⠁⠛⠲⢶⡒⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠉⠂⠀⠀⠀⠀⠤⡙⠢⣄⠀⠀⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⢹⠀⠀⡀⠀⠀⢸⠀⠀⠀⠀⠘⠇⠀⠀⠀⠀⠀⠀⠀⠀⢀⠈⠀⠈⠳⡄⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠣⠀⠀⠈⠀⢀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⢀⡀⠀⠑⠄⠈⠣⡘⢆⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⠀⠀⠀⠀⠀⠿⠀⠀⠀⠀⣠⠞⠉⠀⠀⠀⠀⠙⢆⠀⠀⡀⠀⠁⠈⢇⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⢤⠀⠀⠀⠀⠀⠀⠀⠀⢰⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠙⡄⠀⡀⠈⡆
# ⠀⠀⠀⠀⠀⠀⠀⠀⠸⡆⠘⠃⠀⠀⠀⢀⡄⠀⠀⡇⠀⠀⡄⠀⠀⠀⠰⡀⠀⠀⡄⠀⠉⠀⠃⠀⢱
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⡀⠀⠀⡆⠀⠸⠇⠀⠀⢳⠀⠀⠈⠀⠀⠀⠐⠓⠀⠀⢸⡄⠀⠀⠀⡀⢸
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⡀⠀⢻⠀⠀⠀⠀⢰⠛⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⠀⡆⠀⠃⡼
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣷⣤⣽⣧⠀⠀⠀⡜⠀⠈⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠃
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣇⡿⠹⣷⣄⣬⡗⠢⣤⠖⠛⢳⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠃⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠋⢠⣾⢿⡏⣸⠀⠀⠈⠋⠛⠧⠤⠘⠛⠉⠙⠒⠒⠒⠒⠉⠀⠀⠀
# ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠻⠶⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

#     By: Splunk Threat Research Team [STRT] - research@splunk.com
#     """
#     )




def init_func(config:test):    
    Initialize().execute(config)


def validate_func(config:validate)->DirectorOutputDto:
    validate = Validate()
    return validate.execute(config)

def report_func(config:report)->None:
    # First, perform validation. Remember that the validate
    # configuration is actually a subset of the build configuration
    director_output_dto = validate_func(config)
    
    r = Reporting() 
    return r.execute(ReportingInputDto(director_output_dto=director_output_dto, 
                                       config=config))
    

def build_func(config:build)->DirectorOutputDto:
    # First, perform validation. Remember that the validate
    # configuration is actually a subset of the build configuration
    director_output_dto = validate_func(config)
    builder = Build()
    return builder.execute(BuildInputDto(director_output_dto, config))

def inspect_func(config:inspect)->str:
    #Make sure that we have built the most recent version of the app
    _ = build_func(config)
    inspect_token = Inspect().execute(config)
    return inspect_token
    

def release_notes_func(config:release_notes)->None:
    ReleaseNotes().release_notes(config)

def new_func(config:new):
    NewContent().execute(config)



def deploy_acs_func(config:deploy_acs):
    #This is a bit challenging to get to work with the default values.
    raise Exception("deploy acs not yet implemented") 

def test_common_func(config:test_common):
    if type(config) == test:
        #construct the container Infrastructure objects
        config.getContainerInfrastructureObjects()
        #otherwise, they have already been passed as servers

    director_output_dto = build_func(config)
    gitServer = GitService(director=director_output_dto,config=config)
    detections_to_test = gitServer.getContent()

    

    test_input_dto = TestInputDto(detections_to_test, config)
    
    t = Test()
    
    # Remove detections that we do not want to test because they are
    # not production, the correct type, or manual_test only
    filted_test_input_dto = t.filter_detections(test_input_dto)
    
    if config.plan_only:
        #Emit the test plan and quit. Do not actually run the test
        config.dumpCICDPlanAndQuit(gitServer.getHash(),filted_test_input_dto.detections)
        return 
    
    success = t.execute(filted_test_input_dto)
    
    if success:
        #Everything passed!
        print("All tests have run successfully or been marked as 'skipped'")
        return
    raise Exception("There was at least one unsuccessful test")

def main():
    try:
        configFile = pathlib.Path("contentctl.yml")
        
        # We MUST load a config (with testing info) object so that we can
        # properly construct the command line, including 'contentctl test' parameters.
        if not configFile.is_file():
            if "init" not in sys.argv and "--help" not in sys.argv and "-h" not in sys.argv:
                raise Exception(f"'{configFile}' not found in the current directory.\n"
                                "Please ensure you are in the correct directory or run 'contentctl init' to create a new content pack.")
            
            if "--help" in sys.argv or "-h" in sys.argv:
                print("Warning - contentctl.yml is missing from this directory. The configuration values showed at the default and are informational only.\n"
                      "Please ensure that contentctl.yml exists by manually creating it or running 'contentctl init'")
            # Otherwise generate a stub config file.
            # It will be used during init workflow

            t = test()
            config_obj = t.model_dump()
            
        else:
            #The file exists, so load it up!
            config_obj = YmlReader().load_file(configFile)
            t = test.model_validate(config_obj)
    except Exception as e:
        print(f"Error validating 'contentctl.yml':\n{str(e)}")
        sys.exit(1)
        
    
    # For ease of generating the constructor, we want to allow construction
    # of an object from default values WITHOUT requiring all fields to be declared
    # with defaults OR in the config file. As such, we construct the model rather
    # than model_validating it so that validation does not run on missing required fields.
    # Note that we HAVE model_validated the test object fields already above

    models = tyro.extras.subcommand_type_from_defaults(
        {
            "init":init.model_validate(config_obj),
            "validate": validate.model_validate(config_obj),
            "report": report.model_validate(config_obj),
            "build":build.model_validate(config_obj),
            "inspect": inspect.model_construct(**t.__dict__),
            "new":new.model_validate(config_obj),
            "test":test.model_validate(config_obj),
            "test_servers":test_servers.model_construct(**t.__dict__),
            "release_notes": release_notes.model_construct(**config_obj),
            "deploy_acs": deploy_acs.model_construct(**t.__dict__)
        }
    )
    


   
    config = None
    try:
        # Since some model(s) were constructed and not model_validated, we have to catch
        # warnings again when creating the cli
        with warnings.catch_warnings(action="ignore"):
            config = tyro.cli(models)

        
        if type(config) == init:
            t.__dict__.update(config.__dict__)
            init_func(t)
        elif type(config) == validate:
            validate_func(config)
        elif type(config) == report:
            report_func(config)
        elif type(config) == build:
            build_func(config)
        elif type(config) == new:
            new_func(config)
        elif type(config) == inspect:
            inspect_func(config)
        elif type(config) == release_notes:
            release_notes_func(config)
        elif type(config) == deploy_acs:
            updated_config = deploy_acs.model_validate(config)
            deploy_acs_func(updated_config)
        elif type(config) == test or type(config) == test_servers:
            test_common_func(config)
        else:
            raise Exception(f"Unknown command line type '{type(config).__name__}'")
    except Exception as e:
        if config is None:
            print("There was a serious issue where the config file could not be created.\n"
                  "The entire stack trace is provided below (please include it if filing a bug report).\n")
            traceback.print_exc()
        elif config.verbose:
            print("Verbose error logging is ENABLED.\n"
                  "The entire stack trace has been provided below (please include it if filing a bug report):\n")
            traceback.print_exc()
        else:
            print("Verbose error logging is DISABLED.\n"
                  "Please use the --verbose command line argument if you need more context for your error or file a bug report.")
            print(e)
            
        sys.exit(1)
    