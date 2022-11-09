import sys
import argparse
import os


from splunk_contentctl.actions.validate import ValidateInputDto, Validate
from splunk_contentctl.actions.generate import GenerateInputDto, Generate
from splunk_contentctl.actions.reporting import ReportingInputDto, Reporting
from splunk_contentctl.actions.new_content import NewContentInputDto, NewContent
from splunk_contentctl.actions.doc_gen import DocGenInputDto, DocGen
from splunk_contentctl.input.director import DirectorInputDto
from splunk_contentctl.objects.enums import SecurityContentType, SecurityContentProduct
from splunk_contentctl.enrichments.attack_enrichment import AttackEnrichment
from splunk_contentctl.input.new_content_generator import NewContentGenerator, NewContentGeneratorInputDto
from splunk_contentctl.helper.config_handler import ConfigHandler



def start(args):
    config_path = args.config

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

   # parse config
    config = ConfigHandler.read_config(config_path)
    ConfigHandler.validate_config(config)

    return config 

def configure(args)->None:
    pass
    # import build_skeleton
    # build_skeleton.configure(args)

def initialize(args)->None:
    if args.skip_configuration:
        print("writing default configuration to:  {0}".format(args.output))

        
    pass    
    # import build_skeleton
    # build_skeleton.init(args)

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

def deploy(args) -> None:
    Deploy(args)


def validate(args) -> None:
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
    """
    main function parses the arguments passed to the script and calls the respctive method.
    :param args: arguments passed by the user on command line while calling the script.
    :return: returns the output of the function called.     
    """

    # grab arguments
    parser = argparse.ArgumentParser(
        description="Use `contentctl action -h` to get help with any splunk content action")
    parser.add_argument("-c", "--config", required=False, default="contentctl.yml",
                        help="path to the configuration file of your splunk content, defaults to: contentctl.yml")

    parser.set_defaults(func=lambda _: parser.print_help())
    actions_parser = parser.add_subparsers(title="splunk content actions", dest="action")


    # available actions
    #new_parser = actions_parser.add_parser("new", help="Create new content (detection, story, baseline)")
    init_parser = actions_parser.add_parser("init", help="initialize a splunk content pack using and customizes a configuration under contentctl.yml")
    validate_parser = actions_parser.add_parser("validate", help="validates a splunk content pack")
    build_parser = actions_parser.add_parser("build", help="builds a splunk content pack package to be distributed")
    new_content_parser = actions_parser.add_parser("new", help="create new splunk content object, defaults to")
    reporting_parser = actions_parser.add_parser("report", help="create splunk content report of the current pack")
    inspect_parser = actions_parser.add_parser("inspect", help="runs splunk appinspect on a build splunk app to ensure that an app meets splunkbase requirements.")
    deploy_parser = actions_parser.add_parser("deploy", help="install an application on a target splunk instance.")    


    # init actions
    init_parser.add_argument("-s", "--skip_configuration", required=False, type=argparse.FileType("r"), default=False, help="skips configuration of the pack and generates a default configuration, defaults to False")
    init_parser.add_argument("-o", "--output", required=False, type=argparse.FileType("w"), default='contentctl.yml' )
    init_parser.set_defaults(func=initialize)

    validate_parser.add_argument("-p", "--pack", required=False, type=str, default='SPLUNK_ENTERPRISE_APP', 
                                 help="Type of package to create, choose between all, `SPLUNK_ENTERPRISE_APP` or `SSA`.")
    #validate_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    validate_parser.set_defaults(func=validate)

    build_parser.add_argument("-o", "--output", required=True, type=str,
       help="Path where to store the deployment package")
    build_parser.add_argument("-pr", "--product", required=False, type=str, default="SPLUNK_ENTERPRISE_APP",
       help="Type of package to create, choose between `SPLUNK_ENTERPRISE_APP`, `SSA` or `API`.")
    build_parser.set_defaults(func=generate)
 
    new_content_parser.add_argument("-t", "--type", required=True, type=str,
        help="Type of security content object, choose between `detection`, `story`")
    new_content_parser.add_argument("-o", "--output", required=True, type=str,
        help="output path to store the detection or story")
    new_content_parser.set_defaults(func=new_content)

    reporting_parser.add_argument("-o", "--output", required=True, type=str,
        help="output path to store the detection or story")
    reporting_parser.set_defaults(func=reporting)

    inspect_parser.add_argument("-p", "--app_path", required=False, type=str, default=None, help="path to the splunk app to be inspected")
    inspect_parser.set_defaults(func=inspect)


    deploy_parser.add_argument("-p", "--app_path", required=True, type=str, help="path to the splunk app you wish to deploy")
    deploy_parser.add_argument("--username", required=True, type=str, help="splunk.com username")
    deploy_parser.add_argument("--password", required=True, type=str, help="splunk.com password")
    deploy_parser.add_argument("--server", required=False, default="https://admin.splunk.com", type=str, help="override server URL, defaults to: https://admin.splunk.com")
    deploy_parser.set_defaults(func=deploy)

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

if __name__ == "__main__":
    main(sys.argv[1:])

2                                  