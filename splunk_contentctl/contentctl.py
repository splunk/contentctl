
DEFAULT_CONFIGURE_TEMPLATE_FILE = "app_initialization_template.json"
DEFAULT_CONFIGURE_OUTPUT_FILE =   "app_initialization_configured.json"
from io import TextIOWrapper
import sys
import argparse
import os
import jsonschema
import hierarchy_schema
import json

from bin.contentctl_project.contentctl_core.domain.entities.link_validator import LinkValidator

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'bin/contentctl_project')))

from bin.contentctl_project.contentctl_core.application.use_cases.content_changer import ContentChanger, ContentChangerInputDto
from bin.contentctl_project.contentctl_core.application.use_cases.generate import GenerateInputDto, Generate
from bin.contentctl_project.contentctl_core.application.use_cases.validate import ValidateInputDto, Validate
from bin.contentctl_project.contentctl_core.application.use_cases.doc_gen import DocGenInputDto, DocGen
from bin.contentctl_project.contentctl_core.application.use_cases.new_content import NewContentInputDto, NewContent
from bin.contentctl_project.contentctl_core.application.use_cases.reporting import ReportingInputDto, Reporting
from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryInputDto
from bin.contentctl_project.contentctl_core.application.factory.ba_factory import BAFactoryInputDto
from bin.contentctl_project.contentctl_core.application.factory.new_content_factory import NewContentFactoryInputDto
from bin.contentctl_project.contentctl_core.application.factory.object_factory import ObjectFactoryInputDto
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_object_builder import SecurityContentObjectBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_yml_adapter import ObjToYmlAdapter
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_json_adapter import ObjToJsonAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_conf_adapter import ObjToConfAdapter
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_md_adapter import ObjToMdAdapter
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_svg_adapter import ObjToSvgAdapter
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_attack_nav_adapter import ObjToAttackNavAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_core.application.use_cases.deploy import Deploy
from bin.contentctl_project.contentctl_core.application.use_cases.build import Build
from bin.contentctl_project.contentctl_core.application.use_cases.inspect import Inspect



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
    import build_skeleton
    build_skeleton.configure(args)

def initialize(args)->None:
    
    import build_skeleton
    build_skeleton.init(args)

def content_changer(args) -> None:
    factory_input_dto = ObjectFactoryInputDto(
        os.path.abspath(args.template_answers['output_path']),
        SecurityContentObjectBuilder(),
        SecurityContentDirector()
    )

    input_dto = ContentChangerInputDto(
        ObjToYmlAdapter(args.template_answers['output_path']),
        factory_input_dto,
        args.change_function
    )

    content_changer = ContentChanger()
    content_changer.execute(input_dto)


def generate(args) -> None:
    app_path = os.path.join(args.template_answers['output_path'], args.template_answers['APP_NAME'])
    dist_output_path = os.path.join(app_path, 
                                    'dist', 
                                    args.template_answers['APP_NAME'])

    if 'product' not in args.template_answers:
        print("ERROR: missing name 'product' in template answers.")
        sys.exit(1)     

    if args.template_answers['product'] not in ['SPLUNK_ENTERPRISE_APP', 'SSA', 'API', 'all']:
        print("ERROR: invalid product. valid products are SPLUNK_ENTERPRISE_APP, SSA or API.")
        sys.exit(1)


    if args.cached_and_offline:
        LinkValidator.initialize_cache(args.cached_and_offline)

    #Save runtime by only generating the required factory inputs
    factory_input_dto = None
    ba_factory_input_dto = None
    if args.template_answers['product'] in ["SPLUNK_ENTERPRISE_APP", "API"]:
        factory_input_dto = FactoryInputDto(
            os.path.abspath(app_path),
            SecurityContentBasicBuilder(),
            SecurityContentDetectionBuilder(force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment),
            SecurityContentStoryBuilder(app_name=args.template_answers['APP_NAME']),
            SecurityContentBaselineBuilder(),
            SecurityContentInvestigationBuilder(),
            SecurityContentPlaybookBuilder(input_path=app_path),
            SecurityContentDirector(),
            AttackEnrichment.get_attack_lookup(app_path, force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
        )
    if args.template_answers['product'] in ["SSA", "API"]:
        ba_factory_input_dto = BAFactoryInputDto(
            os.path.abspath(app_path),
            SecurityContentBasicBuilder(),
            SecurityContentDetectionBuilder(force_cached_or_offline = args.cached_and_offline, skip_enrichment=args.skip_enrichment),
            SecurityContentDirector()
        )


    if args.template_answers['product'] == "SPLUNK_ENTERPRISE_APP":
        generate_input_dto = GenerateInputDto(
            os.path.abspath(dist_output_path),
            factory_input_dto,
            ba_factory_input_dto,
            ObjToConfAdapter(app_path, args.template_answers['APP_NAME']),
            SecurityContentProduct.SPLUNK_ENTERPRISE_APP,
        )
    elif args.template_answers['product'] == "API":
        generate_input_dto = GenerateInputDto(
            os.path.abspath(dist_output_path),
            factory_input_dto,
            ba_factory_input_dto,
            ObjToJsonAdapter(),
            SecurityContentProduct.API
        )
    elif args.template_answers['product'] == "SSA":
        generate_input_dto = GenerateInputDto(
            os.path.abspath(dist_output_path),
            factory_input_dto,
            ba_factory_input_dto,
            ObjToYmlAdapter(app_path),
            SecurityContentProduct.SSA
        ) 
    else:
        raise(Exception(f"Unsupported product type {args.template_answers['product']}"))
    generate = Generate()
    generate.execute(generate_input_dto)

    if args.cached_and_offline:
        LinkValidator.close_cache()

def build(args) -> None:
    Build(args)

def inspect(args) -> None:
    Inspect(args)

def cloud_deploy(args) -> None:
    Deploy(args)


def validate(args) -> None:
    app_path = os.path.join(args.template_answers['output_path'], args.template_answers['APP_NAME'])
    
    if 'product' not in args.template_answers:
        print("ERROR: missing name 'product' in template answers.")
        sys.exit(1)     

    if args.template_answers['product'] not in ['SPLUNK_ENTERPRISE_APP', 'SSA', 'all']:
        print("ERROR: invalid product. valid products are all, SPLUNK_ENTERPRISE_APP, or SSA.")
        sys.exit(1)

    if args.cached_and_offline:
        LinkValidator.initialize_cache(args.cached_and_offline)

    #Save runtime by only generating the required factory inputs
    factory_input_dto = None
    ba_factory_input_dto = None
    if args.template_answers['product'] in ["SPLUNK_ENTERPRISE_APP", "all"]:
        factory_input_dto = FactoryInputDto(
            os.path.abspath(app_path),
            SecurityContentBasicBuilder(),
            SecurityContentDetectionBuilder(force_cached_or_offline=args.cached_and_offline, check_references=args.check_references, skip_enrichment=args.skip_enrichment),
            SecurityContentStoryBuilder(check_references=args.check_references, app_name=args.template_answers['APP_NAME']),
            SecurityContentBaselineBuilder(check_references=args.check_references),
            SecurityContentInvestigationBuilder(check_references=args.check_references),
            SecurityContentPlaybookBuilder(input_path=app_path, check_references=args.check_references),
            SecurityContentDirector(),
            AttackEnrichment.get_attack_lookup(app_path, force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
        )
    if args.template_answers['product'] in ["SSA", "all"]:
        ba_factory_input_dto = BAFactoryInputDto(
            os.path.abspath(app_path),
            SecurityContentBasicBuilder(),
            SecurityContentDetectionBuilder(force_cached_or_offline = args.cached_and_offline, check_references=args.check_references, skip_enrichment=args.skip_enrichment),
            SecurityContentDirector()
        )
    
    if args.template_answers['product'] in ["SPLUNK_ENTERPRISE_APP", "all"]:
        validate_input_dto = ValidateInputDto(
            factory_input_dto,
            ba_factory_input_dto,
            SecurityContentProduct.SPLUNK_ENTERPRISE_APP
        )
        validate = Validate()
        validate.execute(validate_input_dto)

    if args.template_answers['product'] in ["SSA", "all"]:
        validate_input_dto = ValidateInputDto(
            factory_input_dto,
            ba_factory_input_dto,
            SecurityContentProduct.SSA
        )
        validate = Validate()
        validate.execute(validate_input_dto)

    if args.cached_and_offline:
        LinkValidator.close_cache()


def doc_gen(args) -> None:
    docgen_output_dir = os.path.join(args.template_answers['output_path'], 
                                args.template_answers['APP_NAME'], 
                                'docs')
    factory_input_dto = FactoryInputDto(
        os.path.abspath(args.template_answers['output_path']),
        SecurityContentBasicBuilder(),
        SecurityContentDetectionBuilder(force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment),
        SecurityContentStoryBuilder(app_name=args.template_answers['APP_NAME']),
        SecurityContentBaselineBuilder(),
        SecurityContentInvestigationBuilder(),
        SecurityContentPlaybookBuilder(input_path=args.args.template_answers['output_path']),
        SecurityContentDirector(),
        AttackEnrichment.get_attack_lookup(args.template_answers['output_path'], force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
    )

    doc_gen_input_dto = DocGenInputDto(
        os.path.abspath(docgen_output_dir),
        factory_input_dto,
        ObjToMdAdapter()
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

    new_content_factory_input_dto = NewContentFactoryInputDto(contentType)
    new_content_input_dto = NewContentInputDto(new_content_factory_input_dto, ObjToYmlAdapter(args.template_answers['output_path']))
    new_content = NewContent()
    new_content.execute(new_content_input_dto)


def reporting(args) -> None:
    factory_input_dto = FactoryInputDto(
        os.path.abspath(args.template_answers['output_path']),
        SecurityContentBasicBuilder(),
        SecurityContentDetectionBuilder(force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment),
        SecurityContentStoryBuilder(app_name=args.template_answers['APP_NAME']),
        SecurityContentBaselineBuilder(),
        SecurityContentInvestigationBuilder(),
        SecurityContentPlaybookBuilder(input_path=args.template_answers['output_path']),
        SecurityContentDirector(),
        AttackEnrichment.get_attack_lookup(args.template_answers['output_path'], force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
    )

    reporting_input_dto = ReportingInputDto(
        factory_input_dto,
        ObjToSvgAdapter(),
        ObjToAttackNavAdapter()
    )

    reporting = Reporting()
    reporting.execute(reporting_input_dto)


def main(args):

    init()

    # grab arguments
    parser = argparse.ArgumentParser(
        description="Use `contentctl.py action -h` to get help with any Splunk Security Content action")
    #parser.add_argument("-p", "--path", required=True, 
    #                                    help="path to the Splunk Security Content folder",)
    parser.add_argument("--cached_and_offline", action=argparse.BooleanOptionalAction,
        help="Force cached/offline resources.  While this makes execution much faster, it may result in enrichment which is out of date. This is suitable for use only in development or disconnected environments.")
    parser.add_argument("--skip_enrichment", action=argparse.BooleanOptionalAction,
        help="Skip enrichment of CVEs.  This can significantly decrease the amount of time needed to run content_ctl.")

    parser.set_defaults(cached_and_offline=False, func=lambda _: parser.print_help())

    
    
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


    configure_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_TEMPLATE_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    configure_parser.add_argument("-ro", "--force_defaults", required=False, action=argparse.BooleanOptionalAction, help="Only create required folders, files, and templates.  Do not ask for user input")
    configure_parser.add_argument("-o", "--output_file", required=False, type=argparse.FileType("w"), default=DEFAULT_CONFIGURE_OUTPUT_FILE )
    configure_parser.set_defaults(func=configure)

    init_parser.add_argument("-c", "--config_file", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help=f"Path to the config template generated by the 'configure' option.  Note that the default output is {DEFAULT_CONFIGURE_OUTPUT_FILE}")
    init_parser.set_defaults(func=initialize)

    #validate_parser.add_argument("-pr", "--product", required=False, type=str, default='SPLUNK_ENTERPRISE_APP', 
    #                             help="Type of package to create, choose between all, `SPLUNK_ENTERPRISE_APP` or `SSA`.")
    validate_parser.add_argument('--check_references', action=argparse.BooleanOptionalAction, help="The number of threads to use to resolve references.  "
                                   "Larger numbers will result in faster resolution, but will be more likely to hit rate limits or use a large amount of "
                                   "bandwidth.  A larger number of threads is particularly useful on high-bandwidth connections, but does not improve "
                                   "performance on slow connections.")
    validate_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    
    validate_parser.set_defaults(func=validate, check_references=False, epilog="""
                Validates security manifest for correctness, adhering to spec and other common items.""")

    #generate_parser.add_argument("-o", "--output", required=True, type=str,
    #    help="Path where to store the deployment package")
    #generate_parser.add_argument("-pr", "--product", required=False, type=str, default="SPLUNK_ENTERPRISE_APP",
    #    help="Type of package to create, choose between `SPLUNK_ENTERPRISE_APP`, `SSA` or `API`.")
    generate_parser.set_defaults(func=generate)
    generate_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    
    content_changer_choices = ContentChanger.enumerate_content_changer_functions()
    content_changer_parser.add_argument("-cf", "--change_function", required=True, metavar='{ ' + ', '.join(content_changer_choices) +' }' , type=str, choices=content_changer_choices, 
                                        help= "Choose from the functions above defined in \nbin/contentctl_core/contentctl/application/use_cases/content_changer.py")
    
    content_changer_parser.set_defaults(func=content_changer)

    #docgen_parser.add_argument("-o", "--output", required=True, type=str,
    #    help="Path where to store the documentation")
    docgen_parser.add_argument("-t", "--template", required=False, type=argparse.FileType("r"), default=DEFAULT_CONFIGURE_OUTPUT_FILE, help="Path to the template which will be used to create a configuration file for generating your app.")
    docgen_parser.set_defaults(func=doc_gen)

    new_content_parser.add_argument("-t", "--type", required=True, type=str,
        help="Type of security content object, choose between `detection`, `story`")
    new_content_parser.set_defaults(func=new_content)

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
        import traceback
        print(traceback.format_exc())


if __name__ == "__main__":
    main(sys.argv[1:])