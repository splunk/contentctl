
DEFAULT_CONFIGURE_TEMPLATE_FILE = "app_initialization_template.json"
DEFAULT_CONFIGURE_OUTPUT_FILE =   "app_initialization_configured.json"
from ast import arg
from codecs import ignore_errors
from io import TextIOWrapper
import shutil
import sys
import argparse
import os

import jsonschema
import hierarchy_schema
import json, yaml

from pydantic import BaseModel
from pydantic.main import ModelMetaclass

from bin.actions.validate import ValidateInputDto, Validate
from bin.actions.generate import GenerateInputDto, Generate
from bin.actions.test import Test
from bin.actions.reporting import ReportingInputDto, Reporting
from bin.actions.new_content import NewContentInputDto, NewContent
from bin.actions.doc_gen import DocGenInputDto, DocGen
from bin.input.director import DirectorInputDto
from bin.objects.enums import SecurityContentType, SecurityContentProduct
from bin.enrichments.attack_enrichment import AttackEnrichment
from bin.input.new_content_generator import NewContentGenerator, NewContentGeneratorInputDto
from bin.objects.test_config import TestConfig
from bin.objects.repo_config import RepoConfig



def create_argparse_parser_from_model(model: BaseModel, parser: argparse.ArgumentParser):
    #Expose all of the fields. Recirsively search for nested Models, too
    for fieldName, fieldItem in model.__fields__.items():            
        if isinstance(fieldItem.type_, ModelMetaclass) and hasattr(fieldItem.default, "__fields__"):
            create_argparse_parser_from_model(fieldItem.default,parser)
        else:
            parser.add_argument(f"--{fieldName}", type=fieldItem.type_, default=None, help=fieldItem.field_info.title)

        
  
def get_configuration_from_command_line(model:BaseModel, args:argparse.Namespace)->BaseModel:
    #Fetch the command line parameters that were passed
    fields_to_update = {}
    for name,value in args.__dict__.items():
        #Only update parameters that exist in the Model and that 
        #are not None.  All of these arguments on the commandLine
        #default to None, making it easy to see whether or not
        #a user has passed a value
        '''
        if value is not None and name in model.__fields__:
            #Command line parameter received an argument. This will override
            #both the default for that arg AND whatever is defined in the
            #config file, if it is passed
            fields_to_update[name] = value
        '''
        if value is not None and name not in ["func", "config_file"]:
            fields_to_update[name] = value
    
    
    
    
    #If a user has passed a config file, use that as the starting point
    #of the configuration
    if args.config_file is not None:
        try:
            #Load the config file
            config = yaml.safe_load(args.config_file)
            #Update the config file with any command line args
            config.update(fields_to_update)
            #build the config object
            return model.parse_obj(config)
        except Exception as e:
            raise(Exception(f"Error parsing config file {args.config_file.name}: {str(e)}"))
            
    else:
        #Parse from the defaults (defined in TestConfig) and the
        #command line parameters. Command line parameters will
        #override any defaults that are set in TestConfig
        try:
            return model.parse_obj(fields_to_update)
        except Exception as e:
            raise(e)






def init():
    return
    print("""
Running Splunk Security Content Control Tool (contentctl) 
starting program loaded for TIE Fighter...
      _                                            _
     T T                                          T T
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                   ____                   | |
     | |            ___.r-"`--'"-r.____           | |
     | |.-._,.,---~"_/_/  .----.  \_\_"~---,.,_,-.| |
     | ]|.[_]_ T~T[_.-Y  / \  / \  Y-._]T~T _[_].|| |
    [|-+[  ___]| [__  |-=[--()--]=-|  __] |[___  ]+-|]
     | ]|"[_]  l_j[_"-l  \ /  \ /  !-"_]l_j  [_]~|| |
     | |`-' "~"---.,_\\"\  "o--o"  /"/_,.---"~" `-'| |
     | |             ~~"^-.____.-^"~~             | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     l_i                                          l_j -Row

    """)


def parse_template(template_file:TextIOWrapper)->dict:
    #Ensure the jsonschema can be loaded and parsed without errors
    try:
        jsonschema.validate({},schema=hierarchy_schema.json_root_schema)
    except Exception as e:
        print(f"Error parsing schema from file {hierarchy_schema.__file__}: {str(e)}")
        sys.exit(1)


    #Load and parse the configuration
    try:
        json_data = json.load(template_file)
    except Exception as e:
        print(f"Error loading json data from {template_file.name}: {str(e)}")
        sys.exit(1)

    #Validate the configuration against the schema
    try:
        jsonschema.validate(json_data, schema=hierarchy_schema.json_root_schema)
    except Exception as e:
        print(f"Error validating json scehma for {template_file.name}: {str(e)}")
        sys.exit(1)

    return json_data


def get_default_answers_from_template(questions:list[dict])->dict:
    answers = {}
    for question in questions:
        name = question['name']
        default = question['default']
        answers[name] = default
    
    return answers



def configure(args)->None:
    #pass
    import build_skeleton
    build_skeleton.configure(args)

def initialize(args)->None:
        
    import build_skeleton
    build_skeleton.init(args)

def content_changer(args) -> None:
    pass


def generate(args) -> None:

    if args.product == 'SPLUNK_ENTERPRISE_APP':
        product = SecurityContentProduct.SPLUNK_ENTERPRISE_APP
    elif args.product == 'SSA':
        product = SecurityContentProduct.SSA
    elif args.product == 'API':
        product = SecurityContentProduct.API
    else:
        print("ERROR: product " + args.product + " not supported")
        sys.exit(1)   

    director_input_dto = DirectorInputDto(
        input_path = args.path,
        product = product,
        create_attack_csv = True,
        skip_enrichment = args.skip_enrichment
    )

    generate_input_dto = GenerateInputDto(
        director_input_dto = director_input_dto,
        product = product,
        output_path = os.path.abspath(args.output)
    )

    generate = Generate()
    generate.execute(generate_input_dto)


def build(args) -> None:
    Build(args)

def inspect(args) -> None:
    Inspect(args)

def cloud_deploy(args) -> None:
    Deploy(args)

'''
# By design, runs validate/generate/build/inspect(optional) before kicking off test
# This way, we can move all of the package generation code out of detection testing,
# Saving us a huge amount of work.
def test(args, force_local_appinspect=False) -> None:
    args.skip_enrichment = True
    args.product = "SPLUNK_ENTERPRISE_APP"
    args.output = os.path.join(args.path, "dist/my_app")
    
    try:
        validate(args)
    except Exception as e:
        print("Test Failed - Error during App Content Validation")
        sys.exit(1)
    
    try:
        generate(args)
    except Exception as e:
        print("Test Failed - Error during App Content Generation")
        sys.exit(1)
    
    
    try:
        build(args)
    except Exception as e:
        print(f"Test Failed - Error during App Build: {str(e)}")
        sys.exit(1)
    
    if force_local_appinspect:
        try:
            inspect(args)
        except Exception as e:
            print("Test Failed - Error during App Inspection")
            sys.exit(1)
    else:
        print("Skipping inspection")
    import bin.detection_testing.detection_testing_execution
    new_argv = ["run", "--mode", "all"]
    bin.detection_testing.detection_testing_execution.main(new_argv)
'''    

def build(args):
    import tarfile
    shutil.rmtree("build", ignore_errors=True)
    os.mkdir("build")

    import pathlib
    sourceDir = pathlib.Path("build/my_app/my_app")
    shutil.copytree(args.output, sourceDir, dirs_exist_ok=True)

    with tarfile.open("build/my_app.tar.gz", "w:gz") as app:
        app.add(sourceDir, arcname="my_app")
    

def test(args):
    
    '''
    #A hack that allow a user to provide a comma-separated list of detections on the command line
    if type(getattr(args, "detections_list", None)) == str:
        args.detections_list = [d.strip() for d in args.detections_list.split(",")]
    
    #Parse everything from the command line
    #test_object = TestConfig.get_configuration_from_command_line(args)
    print(args)
    test_object = get_configuration_from_command_line(RepoConfig, args)
    
    #Run the test
    import pprint
    print("*******")
    print(test_object.dict())
    with open("Res.yml","w") as res:
        
        yaml.dump(test_object.dict(), res)
    '''
    with open("Res.yml","r") as res:
        try:
            data = yaml.safe_load(res)
            if data is None:
                data = {}
        except Exception as e:
            #raise(Exception(f"Error parsing test config: {str(e)}"))
            data = {"test_branch": "doesNotExist"}

        
    test_object = TestConfig.parse_obj(data)
    
    
    Test().execute(test_object)
        


    

    
    
    

    

def validate(args) -> None:

    if args.product == 'SPLUNK_ENTERPRISE_APP':
        product = SecurityContentProduct.SPLUNK_ENTERPRISE_APP
    elif args.product == 'SSA':
        product = SecurityContentProduct.SSA
    else:
        print("ERROR: product " + args.product + " not supported")
        sys.exit(1)   

    director_input_dto = DirectorInputDto(
        input_path = args.path,
        product = product,
        create_attack_csv = False,
        skip_enrichment = args.skip_enrichment
    )

    validate_input_dto = ValidateInputDto(
        director_input_dto = director_input_dto,
        product = SecurityContentProduct.SPLUNK_ENTERPRISE_APP
    )

    validate = Validate()
    validate.execute(validate_input_dto)



def doc_gen(args) -> None:
    director_input_dto = DirectorInputDto(
        input_path = args.path,
        product = SecurityContentProduct.SPLUNK_ENTERPRISE_APP,
        create_attack_csv = False,
        skip_enrichment = args.skip_enrichment
    )

    doc_gen_input_dto = DocGenInputDto(
        director_input_dto = director_input_dto,
        output_path = os.path.abspath(args.output)
    )

    doc_gen = DocGen()
    doc_gen.execute(doc_gen_input_dto)


def new_content(args) -> None:

    if args.type == 'detection':
        contentType = SecurityContentType.detections
    elif args.type == 'story':
        contentType = SecurityContentType.stories
    else:
        print("ERROR: type " + args.type + " not supported")
        sys.exit(1)

    new_content_generator_input_dto = NewContentGeneratorInputDto(type = contentType)
    new_content_input_dto = NewContentInputDto(new_content_generator_input_dto, os.path.abspath(args.output))
    new_content = NewContent()
    new_content.execute(new_content_input_dto)
 

def reporting(args) -> None:

    director_input_dto = DirectorInputDto(
        input_path = args.path,
        product = SecurityContentProduct.SPLUNK_ENTERPRISE_APP,
        create_attack_csv = False,
        skip_enrichment = args.skip_enrichment
    )

    reporting_input_dto = ReportingInputDto(
        director_input_dto = director_input_dto,
        output_path = os.path.abspath(args.output)
    )

    reporting = Reporting()
    reporting.execute(reporting_input_dto)


def main(args):

    init()

    # grab arguments
    parser = argparse.ArgumentParser(
        description="Use `contentctl.py action -h` to get help with any Splunk Security Content action")
    parser.add_argument("-p", "--path", required=True, 
                                        help="path to the Splunk Security Content folder",)
    parser.add_argument("--skip_enrichment", action=argparse.BooleanOptionalAction,
        help="Skip enrichment of CVEs.  This can significantly decrease the amount of time needed to run content_ctl.")

    parser.set_defaults(func=lambda _: parser.print_help())

    
    
    actions_parser = parser.add_subparsers(title="Splunk Security Content actions", dest="action")
    #new_parser = actions_parser.add_parser("new", help="Create new content (detection, story, baseline)")
    configure_parser = actions_parser.add_parser("configure", help="Configure a new app")
    init_parser = actions_parser.add_parser("init", help="Initialize a new app using a configuration created by the 'configure' option")

    validate_parser = actions_parser.add_parser("validate", help="Validates written content")
    generate_parser = actions_parser.add_parser("generate", help="Generates a deployment package for different platforms (splunk_app)")
    content_changer_parser = actions_parser.add_parser("content_changer", help="Change Security Content based on defined rules")
    docgen_parser = actions_parser.add_parser("docgen", help="Generates documentation")
    new_content_parser = actions_parser.add_parser("new_content", help="Create new security content object")
    reporting_parser = actions_parser.add_parser("reporting", help="Create security content reporting")

    build_parser = actions_parser.add_parser("build", help="Build an application suitable for deployment to a search head")
    inspect_parser = actions_parser.add_parser("inspect", help="Run appinspect to ensure that an app meets minimum requirements for deployment.")
    cloud_deploy_parser = actions_parser.add_parser("cloud_deploy", help="Install an application on a target Splunk Cloud Instance.")    

    test_parser = actions_parser.add_parser("test", help="Run a test of the detections locally")

    configure_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_TEMPLATE_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    configure_parser.add_argument("-ro", "--force_defaults", required=False, action=argparse.BooleanOptionalAction, help="Only create required folders, files, and templates.  Do not ask for user input")
    configure_parser.add_argument("-o", "--output_file", required=False, type=argparse.FileType("w"), default=DEFAULT_CONFIGURE_OUTPUT_FILE )
    configure_parser.set_defaults(func=configure)

    init_parser.add_argument("-c", "--config_file", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help=f"Path to the config template generated by the 'configure' option.  Note that the default output is {DEFAULT_CONFIGURE_OUTPUT_FILE}")
    init_parser.set_defaults(func=initialize)

    validate_parser.add_argument("-pr", "--product", required=False, type=str, default='SPLUNK_ENTERPRISE_APP', 
                                 help="Type of package to create, choose between all, `SPLUNK_ENTERPRISE_APP` or `SSA`.")
    #validate_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    validate_parser.set_defaults(func=validate)

    generate_parser.add_argument("-o", "--output", required=True, type=str,
       help="Path where to store the deployment package")
    generate_parser.add_argument("-pr", "--product", required=False, type=str, default="SPLUNK_ENTERPRISE_APP",
       help="Type of package to create, choose between `SPLUNK_ENTERPRISE_APP`, `SSA` or `API`.")
    generate_parser.set_defaults(func=generate)
    #generate_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    
    #content_changer_choices = ContentChanger.enumerate_content_changer_functions()
    #content_changer_parser.add_argument("-cf", "--change_function", required=True, metavar='{ ' + ', '.join(content_changer_choices) +' }' , type=str, choices=content_changer_choices, 
    #                                    help= "Choose from the functions above defined in \nbin/contentctl_core/contentctl/application/use_cases/content_changer.py")
    
    content_changer_parser.set_defaults(func=content_changer)

    docgen_parser.add_argument("-o", "--output", required=True, type=str,
       help="Path where to store the documentation")
    docgen_parser.set_defaults(func=doc_gen)

    new_content_parser.add_argument("-t", "--type", required=True, type=str,
        help="Type of security content object, choose between `detection`, `story`")
    new_content_parser.add_argument("-o", "--output", required=True, type=str,
        help="output path to store the detection or story")
    new_content_parser.set_defaults(func=new_content)

    reporting_parser.add_argument("-o", "--output", required=True, type=str,
        help="output path to store the detection or story")
    reporting_parser.set_defaults(func=reporting)

    #build_parser.add_argument("-o", "--output_dir", required=False, default="build", type=str, help="Directory to output the built package to (default is 'build')")
    #build_parser.add_argument("-pr", "--product", required=True, type=str, help="Name of the product to build. This is the name you created during init.  To find the name of your app, look for the name of the folder created in the ./dist folder.")
    build_parser.set_defaults(func=build)
    build_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")


    inspect_parser.add_argument("-p", "--package_path", required=False, type=str, default=None, help="Path to the package to be inspected")
    inspect_parser.set_defaults(func=inspect)
    inspect_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")


    cloud_deploy_parser.add_argument("--app-package", required=True, type=str, help="Path to the package you wish to deploy")
    cloud_deploy_parser.add_argument("--acs-legal-ack", required=True, type=str, help="specify '--acs-legal-ack=Y' to acknowledge your acceptance of any risks (required)")
    cloud_deploy_parser.add_argument("--username", required=True, type=str, help="splunk.com username")
    cloud_deploy_parser.add_argument("--password", required=True, type=str, help="splunk.com password")
    cloud_deploy_parser.add_argument("--server", required=False, default="https://admin.splunk.com", type=str, help="Override server URL (default 'https://admin.splunk.com')")
    cloud_deploy_parser.set_defaults(func=cloud_deploy)
    
    




    test_parser.add_argument("-c", "--config_file", type=argparse.FileType('r'), default=None, help="Name of the config file to run the test")
    create_argparse_parser_from_model(RepoConfig, test_parser)
    test_parser.set_defaults(func=test)




    # # parse them
    args = parser.parse_args()
    

    
    #Parse the template so that functions don't need to do it individually
    try:
        if 'template' in args and args.template:
            args.template_object = parse_template(args.template)
            args.template_answers = get_default_answers_from_template(args.template_object['questions']) 
    except Exception as e:
        print(f"Error parsing template file {args.template.name}")
        sys.exit(1)
    
    try:
        if 'config_file' in args and args.config_file:
            args.template_object = parse_template(args.config_file)
            args.template_answers = get_default_answers_from_template(args.template_object['questions']) 
    except Exception as e:
        print(f"Error parsing template file {args.config_file.name}")
        sys.exit(1)


    #Catch any errors that aren't otherwise caught and 
    #handled by the parser.
    try:
        return args.func(args)
    except Exception as e:
        print(f"Error for function [{args.func.__name__}]: {str(e)}")
        #import traceback
        #print(traceback.format_exc())

        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv[1:])