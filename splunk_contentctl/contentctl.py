import sys
import argparse
import os

from pydantic import BaseModel
from pydantic.main import ModelMetaclass

from splunk_contentctl.actions.validate import ValidateInputDto, Validate
from splunk_contentctl.actions.generate import GenerateInputDto, DirectorOutputDto, Generate
from splunk_contentctl.actions.reporting import ReportingInputDto, Reporting
from splunk_contentctl.actions.new_content import NewContentInputDto, NewContent
from splunk_contentctl.actions.doc_gen import DocGenInputDto, DocGen
from splunk_contentctl.actions.initialize import NewContentPack
from splunk_contentctl.input.director import DirectorInputDto
from splunk_contentctl.objects.enums import SecurityContentType, SecurityContentProduct
from splunk_contentctl.input.new_content_generator import NewContentGeneratorInputDto
from splunk_contentctl.helper.config_handler import ConfigHandler


from splunk_contentctl.objects.app import App
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.test import Test




def start(args):
    config_path = args.config

    print("""
Running Splunk Security Content Control Tool (contentctl) 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢶⠛⡇⠀⠀⠀⠀⠀⠀⣠⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣀⠼⠖⠛⠋⠉⠉⠓⠢⣴⡻⣾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⡠⠔⠊⠁⠀⠀⠀⠀⠀⠀⣠⣤⣄⠻⠟⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣠⠞⠁⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⢻⣿⣿⠀⢀⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⡇⠀⠀⠀⡠⠊⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠀⠈⠁⠘⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⡉⠓⠒⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢄⠀⠀⠀⠈⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⡇⠀⢠⠀⠀⠀⠀⠀⠀⠀⠈⡷⣄⠀⠀⢀⠈⠀⠀⠑⢄⠀⠑⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠹⡄⠘⡄⠀⠀⠀⠀⢀⡠⠊⠀⠙⠀⠀⠈⢣⠀⠀⠀⢀⠀⠀⠀⠉⠒⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠉⠁⠛⠲⢶⡒⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠉⠂⠀⠀⠀⠀⠤⡙⠢⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢹⠀⠀⡀⠀⠀⢸⠀⠀⠀⠀⠘⠇⠀⠀⠀⠀⠀⠀⠀⠀⢀⠈⠀⠈⠳⡄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠣⠀⠀⠈⠀⢀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⢀⡀⠀⠑⠄⠈⠣⡘⢆⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⠀⠀⠀⠀⠀⠿⠀⠀⠀⠀⣠⠞⠉⠀⠀⠀⠀⠙⢆⠀⠀⡀⠀⠁⠈⢇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⢤⠀⠀⠀⠀⠀⠀⠀⠀⢰⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠙⡄⠀⡀⠈⡆
⠀⠀⠀⠀⠀⠀⠀⠀⠸⡆⠘⠃⠀⠀⠀⢀⡄⠀⠀⡇⠀⠀⡄⠀⠀⠀⠰⡀⠀⠀⡄⠀⠉⠀⠃⠀⢱
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⡀⠀⠀⡆⠀⠸⠇⠀⠀⢳⠀⠀⠈⠀⠀⠀⠐⠓⠀⠀⢸⡄⠀⠀⠀⡀⢸
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⡀⠀⢻⠀⠀⠀⠀⢰⠛⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⠀⡆⠀⠃⡼
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣷⣤⣽⣧⠀⠀⠀⡜⠀⠈⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣇⡿⠹⣷⣄⣬⡗⠢⣤⠖⠛⢳⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠋⢠⣾⢿⡏⣸⠀⠀⠈⠋⠛⠧⠤⠘⠛⠉⠙⠒⠒⠒⠒⠉⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠻⠶⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

    By: Splunk Threat Research Team [STRT] - research@splunk.com
    """)

    # parse config
    config = ConfigHandler.read_config(config_path)
    ConfigHandler.validate_config(config)
    return config 



def initialize(args)->None:
    # start app
    config = start(args)
    NewContentPack(args, config)

def content_changer(args) -> None:
    pass



def build(args) -> DirectorOutputDto:
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
    return generate.execute(generate_input_dto)


def inspect(args) -> None:
    raise(Exception("WARNING - INSPECT NOT YET IMPLEMENTED"))
    #Inspect(args)

def deploy(args) -> None:
    raise(Exception("WARNING - DEPLOY NOT YET IMPLEMENTED"))
    #Deploy(args)


def eric_test(args):
    
    import yaml
    with open("Res.yml","r") as res:
        try:
            data = yaml.safe_load(res)
            test_object = TestConfig.parse_obj(data)
        except Exception as e:
            raise(Exception(f"Error parsing test config: {str(e)}"))
            
    print("Not checking out the specified branch yet.  What should we do? Default to the one in the config? Overwrite the one in the config with the current?")
        
    
    
    args.path = test_object.repo_path
    args.product = "SPLUNK_ENTERPRISE_APP"
    args.output = os.path.join(test_object.repo_path, "dist","escu")
    args.skip_enrichment = True
    
    
    director = build(args)
    import pprint
    
    

    app = build(args)
    
    a = App(uid=9999, appid="my_custom_app", title="my_custom_app",
            release="1.0.0",local_path=str(app), description="lame description", http_path=None, splunkbase_path=None)

    test_object.apps.append(a)
    print(f"generate complete. written to {args.output}")
    
    Test().execute(test_object, director)
        


def validate(args) -> DirectorOutputDto:
    config = start(args)
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
    return validate.execute(validate_input_dto)
    
    



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
    """
    main function parses the arguments passed to the script and calls the respctive method.
    :param args: arguments passed by the user on command line while calling the script.
    :return: returns the output of the function called.     
    """

    # grab arguments
    parser = argparse.ArgumentParser(
        description="Use `contentctl action -h` to get help with any Splunk content action")
    parser.add_argument("-c", "--config", required=False, default="contentctl.yml",
                        help="path to the configuration file of your Splunk content, defaults to: contentctl.yml")

    parser.set_defaults(func=lambda _: parser.print_help())
    actions_parser = parser.add_subparsers(title="Splunk content actions", dest="action")

    # available actions
    init_parser = actions_parser.add_parser("init", help="initialize a Splunk content pack using and customizes a configuration under contentctl.yml")
    validate_parser = actions_parser.add_parser("validate", help="validates a Splunk content pack")
    build_parser = actions_parser.add_parser("build", help="builds a Splunk content pack package to be distributed")
    new_content_parser = actions_parser.add_parser("new", help="create new Splunk content object (detection, or story)")
    reporting_parser = actions_parser.add_parser("report", help="create Splunk content report of the current pack")
    inspect_parser = actions_parser.add_parser("inspect", help="runs Splunk appinspect on a build Splunk app to ensure that an app meets Splunkbase requirements.")
    deploy_parser = actions_parser.add_parser("deploy", help="install an application on a target Splunk instance.")  
    test_parser = actions_parser.add_parser("test", help="test Splunk content detections inside a docker instance.")    

    test_parser = actions_parser.add_parser("test", help="Run a test of the detections locally")

    # init actions
    init_parser.add_argument("-s", "--skip_configuration", action='store_true', required=False, default=False, help="skips configuration of the pack and generates a default configuration")
    init_parser.add_argument("-o", "--output", required=False, type=str, default='.', help="output directory to initialize the content pack in" )
    init_parser.set_defaults(func=initialize)

    validate_parser.add_argument("-p", "--pack", required=False, type=str, default='SPLUNK_ENTERPRISE_APP', 
                                 help="Type of package to create, choose between all, `SPLUNK_ENTERPRISE_APP` or `SSA`.")
    #validate_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    validate_parser.set_defaults(func=validate)

    build_parser.add_argument("-o", "--output", required=True, type=str,
       help="Path where to store the deployment package")
    build_parser.add_argument("-pr", "--product", required=False, type=str, default="SPLUNK_ENTERPRISE_APP",
       help="Type of package to create, choose between `SPLUNK_ENTERPRISE_APP`, `SSA` or `API`.")
    build_parser.set_defaults(func=build)
 
    new_content_parser.add_argument("-t", "--type", required=True, type=str,
        help="Type of security content object, choose between `detection`, `story`")
    new_content_parser.add_argument("-o", "--output", required=True, type=str,
        help="output path to store the detection or story")
    new_content_parser.set_defaults(func=new_content)

    reporting_parser.add_argument("-o", "--output", required=True, type=str,
        help="output path to store the detection or story")
    reporting_parser.set_defaults(func=reporting)

    inspect_parser.add_argument("-p", "--app_path", required=False, type=str, default=None, help="path to the Splunk app to be inspected")
    inspect_parser.set_defaults(func=inspect)


    deploy_parser.add_argument("-p", "--app_path", required=True, type=str, help="path to the Splunk app you wish to deploy")
    deploy_parser.add_argument("--username", required=True, type=str, help="splunk.com username")
    deploy_parser.add_argument("--password", required=True, type=str, help="splunk.com password")
    deploy_parser.add_argument("--server", required=False, default="https://admin.splunk.com", type=str, help="override server URL, defaults to: https://admin.splunk.com")
    deploy_parser.set_defaults(func=deploy)


    test_parser.set_defaults(func=eric_test)

    # parse them
    args = parser.parse_args()
    

    #Catch any errors that aren't otherwise caught and 
    #handled by the parser.
    try:
        return args.func(args)
    except Exception as e:
        print(f"Error for function [{args.func.__name__}]: {str(e)}")
        import traceback
        print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])

                                  