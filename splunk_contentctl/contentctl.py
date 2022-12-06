import sys
import argparse
import os

import yaml


from splunk_contentctl.actions.validate import ValidateInputDto, Validate
from splunk_contentctl.actions.generate import GenerateInputDto, DirectorOutputDto, Generate
from splunk_contentctl.actions.reporting import ReportingInputDto, Reporting
from splunk_contentctl.actions.new_content import NewContentInputDto, NewContent
from splunk_contentctl.actions.doc_gen import DocGenInputDto, DocGen
from splunk_contentctl.actions.initialize import Initialize, InitializeInputDto
from splunk_contentctl.input.director import DirectorInputDto
from splunk_contentctl.objects.enums import SecurityContentType, SecurityContentProduct
from splunk_contentctl.input.new_content_generator import NewContentGeneratorInputDto
from splunk_contentctl.helper.config_handler import ConfigHandler

from splunk_contentctl.objects.config import Config

from splunk_contentctl.objects.app import App
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.test import Test





def print_ascii_art():
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


def start(args)->Config:
    print_ascii_art()
    return ConfigHandler.read_config(os.path.join(args.path, 'contentctl.yml'))





def initialize(args)->None:
    print_ascii_art()
    Initialize().execute(
        InitializeInputDto(
            path=os.path.abspath(args.path)
        )
    )


#REMOVE AFTER TEST INTEGRATION IS COMPLETE
#extra config argument is only here for test integration work
from typing import Union
def build(args, config: Union[Config,None] = None) -> DirectorOutputDto:
    #REMOVE AFTER TEST INTEGRATION IS COMPLETE
    if config is None:
        config = start(args)
    else:
        print("Using a hardcoded config for contentctl test integration")

    product_type = SecurityContentProduct.splunk_app
    print("only attempting to generate splunk_app")
    director_input_dto = DirectorInputDto(
            args.path,
            product_type,
            config = config
        )


    generate_input_dto = GenerateInputDto(
        director_input_dto,
        product_type,
        output_path = config.build.splunk_app.path
    )

    generate = Generate()

    director = generate.execute(generate_input_dto)
    return director
    #END REMOVE AFTER TEST INTEGRATION IS COMPLETE
    

    for product_type in config.build:
        
        if product_type not in SecurityContentProduct:
            raise(Exception(f"Unsupported product type {product_type} found in configuration file {args.config}.\n"
                             f"Only the following product types are valid: {SecurityContentProduct._member_names_}"))
        
        
        director_input_dto = DirectorInputDto(
            args.path,
            product_type,
            config = config
        )


        generate_input_dto = GenerateInputDto(
            director_input_dto,
            product_type,
            output_path = config.build.splunk_app.path
        )

        generate = Generate()

        #REMOVE AFTER TEST INTEGRATION IS COMPLETE
        director = generate.execute(generate_input_dto)






def inspect(args) -> None:
    raise(Exception("WARNING - INSPECT NOT YET IMPLEMENTED"))
    #Inspect(args)

def deploy(args) -> None:
    raise(Exception("WARNING - DEPLOY NOT YET IMPLEMENTED"))
    #Deploy(args)



def eric_test(args):
    '''
    import yaml
    with open("Res.yml","r") as res:
        try:
            data = yaml.safe_load(res)
            test_object = TestConfig.parse_obj(data)
        except Exception as e:
            raise(Exception(f"Error parsing test config: {str(e)}"))
    '''     
    print("security_content repo MUST be checked out into '/tmp/security_content' - this requirement is just for initial testing")
    
    args.path = "/tmp/security_content"
    args.output = os.path.join(args.path, "dist","escu")
    
    config = start(args)
    

    director = build(args, config)
    
    import pathlib
    app_path = pathlib.Path(config.build.splunk_app.path)
    archive_path = f"{str(app_path)}.tar.gz"
    print(f"tar.gz'ing {app_path} so it can be installed as an app")
    import tarfile
    with tarfile.open(archive_path, "w:gz") as app_archive:
        app_archive.add(app_path, arcname=app_path.name)

    test_config = TestConfig.parse_obj({'repo_path': args.path})
    
    

    a = App(uid=9999, appid="my_custom_app", title="my_custom_app",
            release="1.0.0",local_path=archive_path, description="lame description", http_path=None, splunkbase_path=None)
    
    test_config.apps.append(a)

    Test().execute(test_config, director)
        



def validate(args) -> None:
    config = start(args)


    director_input_dto = DirectorInputDto(
        input_path = os.path.abspath(args.path),
        product = SecurityContentProduct[args.product],
        config = config
    )

    validate_input_dto = ValidateInputDto(
        director_input_dto = director_input_dto
    )

    validate = Validate()
    return validate.execute(validate_input_dto)
    
    


def doc_gen(args) -> None:
    director_input_dto = DirectorInputDto(
        input_path = args.path,
        product = SecurityContentProduct.splunk_app,
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
        product = SecurityContentProduct.splunk_app,
        create_attack_csv = False,
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
    parser.add_argument("-p", "--path", required=False, default=".",
                        help="path to the content path containing the contentctl.yml")

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

    test_parser = actions_parser.add_parser("test", help="Run a test of the detections against a Splunk Server or Splunk Docker Container")

    # init actions
    #init_parser.add_argument("-s", "--skip_configuration", action='store_true', required=False, default=False, help="skips configuration of the pack and generates a default configuration")
    #init_parser.add_argument("-o", "--output", required=False, type=str, default='.', help="output directory to initialize the content pack in" )
    init_parser.set_defaults(func=initialize)

    #validate_parser.add_argument("-p", "--pack", required=False, type=str, default='SPLUNK_ENTERPRISE_APP', 
    #                             help="Type of package to create, choose between all, `SPLUNK_ENTERPRISE_APP` or `SSA`.")
    #validate_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    validate_parser.add_argument("-pr", "--product", required=False, type=str, default="splunk_app",
       help="Type of package to create, choose between .")
    validate_parser.set_defaults(func=validate)

    #These arguments are not required because they will be read from the config
    build_parser.add_argument("-o", "--output", required=False, type=str,
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

    inspect_parser.add_argument("-ap", "--app_path", required=False, type=str, default=None, help="path to the Splunk app to be inspected")
    inspect_parser.set_defaults(func=inspect)


    deploy_parser.add_argument("-ap", "--app_path", required=True, type=str, help="path to the Splunk app you wish to deploy")
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