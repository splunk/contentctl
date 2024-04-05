import sys
import argparse
import os
import tqdm
import functools
from typing import Union
import pathlib
import yaml
from contentctl.actions.detection_testing.GitService import (
    GitService,
)
from contentctl.actions.validate import ValidateInputDto, Validate
from contentctl.actions.generate import (
    GenerateInputDto,
    DirectorOutputDto,
    Generate,
)
from contentctl.actions.acs_deploy import ACSDeployInputDto, Deploy

from contentctl.actions.reporting import ReportingInputDto, Reporting
from contentctl.actions.new_content import NewContentInputDto, NewContent
from contentctl.actions.doc_gen import DocGenInputDto, DocGen
from contentctl.actions.initialize import Initialize, InitializeInputDto
from contentctl.actions.api_deploy import API_Deploy, API_DeployInputDto
from contentctl.actions.release_notes import ReleaseNotesInputDto, ReleaseNotes
from contentctl.input.director import DirectorInputDto
from contentctl.objects.enums import (
    SecurityContentType,
    SecurityContentProduct,
    DetectionTestingMode,
    PostTestBehavior,
    DetectionTestingTargetInfrastructure,
    SigmaConverterTarget
)
from contentctl.input.new_content_generator import NewContentGeneratorInputDto
from contentctl.helper.config_handler import ConfigHandler

from contentctl.objects.config import Config

from contentctl.objects.app import App
from contentctl.objects.test_config import Infrastructure
from contentctl.actions.test import Test, TestInputDto
from contentctl.input.sigma_converter import SigmaConverterInputDto
from contentctl.actions.convert import ConvertInputDto, Convert


SERVER_ARGS_ENV_VARIABLE = "CONTENTCTL_TEST_INFRASTRUCTURES"


def configure_unattended(args: argparse.Namespace) -> argparse.Namespace:
    # disable all calls to tqdm - this is so that CI/CD contexts don't
    # have a large amount of output due to progress bar updates.
    tqdm.tqdm.__init__ = functools.partialmethod(
        tqdm.tqdm.__init__, disable=args.unattended
    )
    if args.unattended:
        if args.behavior != PostTestBehavior.never_pause.name:
            print(
                f"For unattended mode, --behavior MUST be {PostTestBehavior.never_pause.name}.\n"
                f"Updating the behavior from '{args.behavior}' to "
                f"'{PostTestBehavior.never_pause.name}'"
            )
            args.behavior = PostTestBehavior.never_pause.name

    return args


def print_ascii_art():
    print(
        """
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
    """
    )


def start(args: argparse.Namespace, read_test_file: bool = False) -> Config:
    base_config = ConfigHandler.read_config(args)
    if read_test_file:
        base_config.test = ConfigHandler.read_test_config(args)
    return base_config


def initialize(args) -> None:
    Initialize().execute(InitializeInputDto(path=pathlib.Path(args.path), demo=args.demo))


def build(args, config: Union[Config, None] = None) -> DirectorOutputDto:
    if config is None:
        config = start(args)
    if args.type == "app":
        product_type = SecurityContentProduct.SPLUNK_APP
    elif args.type == "ssa":
        product_type = SecurityContentProduct.SSA
    elif args.type == "api":
        product_type = SecurityContentProduct.API
    else:
        print("Invalid build type. Valid options app, ssa or api")
        sys.exit(1)
    director_input_dto = DirectorInputDto(
        input_path=pathlib.Path(os.path.abspath(args.path)), 
        product=product_type, 
        config=config
    )
    generate_input_dto = GenerateInputDto(
        director_input_dto,
        args.splunk_api_username,
        args.splunk_api_password,
    )

    generate = Generate()

    return generate.execute(generate_input_dto)


def api_deploy(args) -> None:
    config = start(args)
    deploy_input_dto = API_DeployInputDto(path=pathlib.Path(args.path), config=config)
    deploy = API_Deploy()

    deploy.execute(deploy_input_dto)


def acs_deploy(args) -> None:
    config = start(args)
    director_input_dto = DirectorInputDto(
        input_path=pathlib.Path(os.path.abspath(args.path)), 
        product=SecurityContentProduct.SPLUNK_APP, 
        config=config
    )
    acs_deply_dto = ACSDeployInputDto(director_input_dto, 
                      args.splunk_api_username, 
                      args.splunk_api_password, 
                      args.splunk_cloud_jwt_token, 
                      args.splunk_cloud_stack, 
                      args.stack_type)
    
    deploy = Deploy()
    deploy.execute(acs_deply_dto)

    


def test(args: argparse.Namespace):
    args = configure_unattended(args)

    config = start(args, read_test_file=True)
    #Don't do enrichment
    if args.dry_run:
        config.enrichments.attack_enrichment = False
        config.enrichments.cve_enrichment = False
        config.enrichments.splunk_app_enrichment = False

    if config.test is None:
        raise Exception("Error parsing test configuration. Test Object was None.")

    if args.test_branch is not None:
        if config.test.version_control_config is not None:
            config.test.version_control_config.test_branch = args.test_branch
        else:
            raise Exception("Test argument 'test_branch' passed on the command line, but 'version_control_config' is not defined in contentctl_test.yml.")
    if args.target_branch is not None:
        if config.test.version_control_config is not None:
            config.test.version_control_config.target_branch = args.target_branch
        else:
            raise Exception("Test argument 'target_branch' passed on the command line, but 'version_control_config' is not defined in contentctl_test.yml.")
        
    # set some arguments that are not
    # yet exposed/written properly in
    # the config file
    if args.infrastructure is not None:
        config.test.infrastructure_config.infrastructure_type = DetectionTestingTargetInfrastructure(
            args.infrastructure
        )
    if args.mode is not None:
        config.test.mode = DetectionTestingMode(args.mode)
    if args.behavior is not None:
        config.test.post_test_behavior = PostTestBehavior(args.behavior)
    if args.detections_list is not None:
        config.test.detections_list = args.detections_list
    if args.enable_integration_testing or config.test.enable_integration_testing:
        config.test.enable_integration_testing = True

    # validate and setup according to infrastructure type
    if config.test.infrastructure_config.infrastructure_type == DetectionTestingTargetInfrastructure.container:
        if args.num_containers is None:
            raise Exception(
                "Error - trying to start a test using container infrastructure but no value for --num_containers was "
                "found"
            )
        config.test.infrastructure_config.infrastructures = Infrastructure.get_infrastructure_containers(
            args.num_containers
        )
    elif config.test.infrastructure_config.infrastructure_type == DetectionTestingTargetInfrastructure.server:
        if args.server_info is None and os.environ.get(SERVER_ARGS_ENV_VARIABLE) is None:
            if len(config.test.infrastructure_config.infrastructures) == 0:
                raise Exception(
                    "Error - trying to start a test using server infrastructure, but server information was not stored "
                    "in contentctl_test.yml or passed on the command line. Please see the documentation for "
                    "--server_info at the command line or 'infrastructures' in contentctl.yml."
                )
            else:
                print("Using server configuration from: [contentctl_test.yml infrastructures section]")

        else:
            if args.server_info is not None:
                print("Using server configuration from: [command line]")
                pass
            elif os.environ.get(SERVER_ARGS_ENV_VARIABLE) is not None:
                args.server_info = os.environ.get(SERVER_ARGS_ENV_VARIABLE, "").split(';')
                print(f"Using server configuration from: [{SERVER_ARGS_ENV_VARIABLE} environment variable]")
            else:
                raise Exception(
                    "Server infrastructure information not passed in contentctl_test.yml file, using --server_info "
                    f"switch on the command line, or in the {SERVER_ARGS_ENV_VARIABLE} environment variable"
                )
                # if server info was provided on the command line, us that. Otherwise use the env

            config.test.infrastructure_config.infrastructures = []

            for server in args.server_info:
                address, username, password, web_ui_port, hec_port, api_port = server.split(",")
                config.test.infrastructure_config.infrastructures.append(
                    Infrastructure(
                        splunk_app_username=username,
                        splunk_app_password=password,
                        instance_address=address,
                        hec_port=int(hec_port),
                        web_ui_port=int(web_ui_port),
                        api_port=int(api_port)
                    )
                )

    # We do this before generating the app to save some time if options are incorrect.
    # For example, if the detection(s) we are trying to test do not exist
    gitService = GitService(config.test)

    

    director_output_dto = build(args, config)

    test_director_output_dto = gitService.get_all_content(director_output_dto)
    
    if args.dry_run:
        #set the proper values in the config
        config.test.mode = DetectionTestingMode.selected
        config.test.detections_list = [d.file_path for d in test_director_output_dto.detections]
        config.test.apps = []
        config.test.post_test_behavior = PostTestBehavior.never_pause
        
        #Disable enrichments to save time
        config.enrichments.attack_enrichment = False
        config.enrichments.cve_enrichment = False
        config.enrichments.splunk_app_enrichment = False
        
        #Create a directory for artifacts.
        dry_run_config_dir = pathlib.Path("dry_run_config")
        
        #It's okay if it already exists
        dry_run_config_dir.mkdir(exist_ok=True)

        #Write out the test plan file
        with open(dry_run_config_dir/"contentctl_test.yml", "w") as test_plan_config:
            d = config.test.dict()
            d['infrastructure_config']['infrastructure_type'] = d['infrastructure_config']['infrastructure_type'].value
            d['mode'] = d['mode'].value
            d['post_test_behavior'] = d['post_test_behavior'].value
            yaml.safe_dump(d, test_plan_config)
        
        with open(dry_run_config_dir/"contentctl.yml", "w") as contentctl_cfg:
            d = config.dict()
            del d["test"]
            yaml.safe_dump(d, contentctl_cfg)
        

        
        print(f"Wrote test plan to '{dry_run_config_dir/'contentctl_test.yml'}' and '{dry_run_config_dir/'contentctl.yml'}'")
        return



    else:
        # All this information will later come from the config, so we will
        # be able to do it in Test().execute. For now, we will do it here
        app = App(
            uid=9999,
            appid=config.build.name,
            title=config.build.title,
            release=config.build.version,
            http_path=None,
            local_path=str(pathlib.Path(config.build.path_root)/f"{config.build.name}-{config.build.version}.tar.gz"),
            description=config.build.description,
            splunkbase_path=None,
            force_local=True
        )

        # We need to do this instead of appending to retrigger validation.
        # It does not happen the first time since validation does not run for default values
        # unless we use always=True in the validator
        # we always want to keep CIM as the last app installed

        config.test.apps = [app] + config.test.apps

    test_input_dto = TestInputDto(
        test_director_output_dto=test_director_output_dto,
        gitService=gitService,
        config=config.test,
    )

    test = Test()

    result = test.execute(test_input_dto)
    # This return code is important.  Even if testing
    # fully completes, if everything does not pass then
    # we want to return a nonzero status code
    if result:
        return
    else:
        sys.exit(1)


def validate(args) -> None:
    config = start(args)
    if args.type == "app":
        product_type = SecurityContentProduct.SPLUNK_APP
    elif args.type == "ssa":
        product_type = SecurityContentProduct.SSA
    elif args.type == "api":
        product_type = SecurityContentProduct.API
    else:
        print("Invalid build type. Valid options app, ssa or api")
        sys.exit(1)
    director_input_dto = DirectorInputDto(
        input_path=pathlib.Path(args.path),
        product=product_type,
        config=config
    )
    validate_input_dto = ValidateInputDto(director_input_dto=director_input_dto)
    validate = Validate()
    return validate.execute(validate_input_dto)

def release_notes(args)-> None:

    config = start(args)
    director_input_dto = DirectorInputDto(
        input_path=pathlib.Path(args.path), product=SecurityContentProduct.SPLUNK_APP, config=config
    )

    release_notes_input_dto = ReleaseNotesInputDto(director_input_dto=director_input_dto)

    release_notes = ReleaseNotes()
    release_notes.release_notes(release_notes_input_dto, args.old_tag, args.new_tag, args.latest_branch)

def doc_gen(args) -> None:
    config = start(args)
    director_input_dto = DirectorInputDto(
        input_path=pathlib.Path(args.path), product=SecurityContentProduct.SPLUNK_APP, config=config
    )

    doc_gen_input_dto = DocGenInputDto(director_input_dto=director_input_dto)

    doc_gen = DocGen()
    doc_gen.execute(doc_gen_input_dto)


def new_content(args) -> None:

    if args.type == "detection":
        contentType = SecurityContentType.detections
    elif args.type == "story":
        contentType = SecurityContentType.stories
    else:
        print("ERROR: type " + args.type + " not supported")
        sys.exit(1)

    new_content_generator_input_dto = NewContentGeneratorInputDto(type=contentType)
    new_content_input_dto = NewContentInputDto(
        new_content_generator_input_dto, os.path.abspath(args.path)
    )
    new_content = NewContent()
    new_content.execute(new_content_input_dto)


def reporting(args) -> None:
    config = start(args)
    director_input_dto = DirectorInputDto(
        input_path=args.path, product=SecurityContentProduct.SPLUNK_APP, config=config
    )

    reporting_input_dto = ReportingInputDto(director_input_dto=director_input_dto)

    reporting = Reporting()
    reporting.execute(reporting_input_dto)


def convert(args) -> None:
    if args.data_model == 'cim':
        data_model = SigmaConverterTarget.CIM
    elif args.data_model == 'raw':
        data_model = SigmaConverterTarget.RAW
    elif args.data_model == 'ocsf':
        data_model = SigmaConverterTarget.OCSF
    else:
        print("ERROR: data model " + args.data_model + " not supported")
        sys.exit(1)

    sigma_converter_input_dto = SigmaConverterInputDto(
        data_model=data_model,
        detection_path=args.detection_path,
        detection_folder=args.detection_folder,
        input_path=args.path,
        log_source=args.log_source
    )

    convert_input_dto = ConvertInputDto(
        sigma_converter_input_dto=sigma_converter_input_dto,
        output_path=os.path.abspath(args.output)
    )
    convert = Convert()
    convert.execute(convert_input_dto)


def main():
    """
    main function parses the arguments passed to the script and calls the respctive method.
    :param args: arguments passed by the user on command line while calling the script.
    :return: returns the output of the function called.
    """

    # grab arguments
    parser = argparse.ArgumentParser(
        description="Use `contentctl action -h` to get help with any Splunk content action"
    )
    parser.add_argument(
        "-p",
        "--path",
        required=False,
        default=".",
        help="path to the content path containing the contentctl.yml",
    )

    parser.add_argument(
        "--enable_enrichment",
        required=False,
        action="store_true",
        help="Enrichment is only REQUIRED when building a release (or testing a release). In most cases, it is not required. Disabling enrichment BY DEFAULT (which is the default setting in contentctl.yml) is a signifcant time savings."
    )

    parser.set_defaults(func=lambda _: parser.print_help())
    actions_parser = parser.add_subparsers(
        title="Splunk content actions", dest="action"
    )

    # available actions
    init_parser = actions_parser.add_parser(
        "init",
        help="initialize a Splunk content pack using and customizes a configuration under contentctl.yml",
    )
    validate_parser = actions_parser.add_parser(
        "validate", help="validates a Splunk content pack"
    )
    build_parser = actions_parser.add_parser(
        "build", help="builds a Splunk content pack package to be distributed"
    )

    acs_deploy_parser = actions_parser.add_parser(
        "acs_deploy", help="Deploys a previously built package via ACS.  Note that 'contentctl build' command MUST have been run prior to running this command. It will NOT build a package itself."
    )

    new_content_parser = actions_parser.add_parser(
        "new", help="create new Splunk content object (detection, or story)"
    )
    reporting_parser = actions_parser.add_parser(
        "report", help="create Splunk content report of the current pack"
    )

    api_deploy_parser = actions_parser.add_parser(
        "api_deploy", help="Deploy content via API to a target Splunk Instance."
    )

    docs_parser = actions_parser.add_parser(
        "docs", help="create documentation in docs folder"
    )
    release_notes_parser = actions_parser.add_parser(
        "release_notes",
        help="Compares two tags and create release notes of what ESCU/BA content is added"
    )

    test_parser = actions_parser.add_parser(
        "test",
        help="Run a test of the detections against a Splunk Server or Splunk Docker Container",
    )

    convert_parser = actions_parser.add_parser("convert", help="Convert a sigma detection to a Splunk ESCU detection.")

    init_parser.set_defaults(func=initialize)
    init_parser.add_argument(
        "--demo",
        action=argparse.BooleanOptionalAction,
        help=(
            "Use this flag to pre-populate the content pack "
            "with one additional detection that will fail 'contentctl validate' "
            "and on detection that will fail 'contentctl test'.  This is useful "
            "for demonstrating contentctl functionality."
        )
    )

    validate_parser.add_argument(
        "-t",
        "--type",
        required=False,
        type=str,
        default="app",
        help="Type of package: app, ssa or api"
    )
    validate_parser.set_defaults(func=validate)

    build_parser.add_argument(
        "-t",
        "--type",
        required=False,
        type=str,
        default="app",
        help="Type of package: app, ssa or api"
    )

    build_parser.add_argument(
        "--splunk_api_username",
        required=False,
        type=str,
        default=None,
        help=(
            f"Username for running AppInspect and, if desired, installing your app via Admin Config Service (ACS). For documentation, "
            "please review https://dev.splunk.com/enterprise/reference/appinspect/appinspectapiepref and https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/Config/ManageApps"
        )
    )
    build_parser.add_argument(
        "--splunk_api_password",
        required=False,
        type=str,
        default=None,
        help=(
            f"Username for running AppInspect and, if desired, installing your app via Admin Config Service (ACS). For documentation, "
            "please review https://dev.splunk.com/enterprise/reference/appinspect/appinspectapiepref and https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/Config/ManageApps"
        )
    )


    build_parser.set_defaults(func=build)


    acs_deploy_parser.add_argument(
        "--splunk_api_username",
        required=True,
        type=str,
        help=(
            f"Username for running AppInspect and, if desired, installing your app via Admin Config Service (ACS). For documentation, "
            "please review https://dev.splunk.com/enterprise/reference/appinspect/appinspectapiepref and https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/Config/ManageApps"
        )
    )
    acs_deploy_parser.add_argument(
        "--splunk_api_password",
        required=True,
        type=str,
        help=(
            f"Username for running AppInspect and, if desired, installing your app via Admin Config Service (ACS). For documentation, "
            "please review https://dev.splunk.com/enterprise/reference/appinspect/appinspectapiepref and https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/Config/ManageApps"
        )
    )
    
    acs_deploy_parser.add_argument(
        "--splunk_cloud_jwt_token",
        required=True,
        type=str,
        help=(
            f"Target Splunk Cloud Stack JWT Token for app deployment.  Note that your stack MUST Support Admin Config Server (ACS) and Automated Private App Vetting (APAV). For documentation, "
            "on creating this token, please review https://docs.splunk.com/Documentation/SplunkCloud/9.1.2312/Security/CreateAuthTokens#Use_Splunk_Web_to_create_authentication_tokens"
        )
    )

    acs_deploy_parser.add_argument(
        "--splunk_cloud_stack",
        required=True,
        type=str,
        help=(
            f"Target Splunk Cloud Stack for app deployment.  Note that your stack MUST Support Admin Config Server (ACS) and Automated Private App Vetting (APAV). For documentation, "
            "please review https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/Config/ManageApps"
        )
    )

    acs_deploy_parser.add_argument(
        "--stack_type",
        required=True,
        type=str,
        choices=["classic","victoria"],
        help="Identifies your Splunk Cloud Stack as 'classic' or 'victoria' experience"
    )


    acs_deploy_parser.set_defaults(func=acs_deploy)

    docs_parser.set_defaults(func=doc_gen)

    new_content_parser.add_argument(
        "-t",
        "--type",
        required=True,
        type=str,
        help="Type of security content object, choose between `detection`, `story`",
    )
    new_content_parser.set_defaults(func=new_content)

    reporting_parser.set_defaults(func=reporting)

    api_deploy_parser.set_defaults(func=api_deploy)

    test_parser.add_argument(
        "-t",
        "--type",
        required=False,
        type=str,
        default="app",
        help="Type of package: app, ssa or api"
    )
    test_parser.add_argument(
        "--mode",
        required=False,
        default=None,
        type=str,
        choices=DetectionTestingMode._member_names_,
        help="Controls which detections to test. 'all' will test all detections in the repo."
        "'selected' will test a list of detections that have "
        "been provided via the --selected command line argument (see for more details).",
    )
    test_parser.add_argument(
        "--behavior",
        required=False,
        default=None,
        type=str,
        choices=PostTestBehavior._member_names_,
        help="Controls what to do when a test completes. 'always_pause' means that the state of "
        "the test will always pause after a test, allowing the user to log into the "
        "server and experiment with the search and data before it is removed.  'pause_on_failure' "
        "will pause execution ONLY when a test fails. The user may press ENTER in the terminal "
        "running the test to move on to the next test.  'never_pause' will never stop testing, "
        "even if a test fails. Please note that 'never_pause' MUST be used for a test to "
        "run in an unattended manner or in a CI/CD system - otherwise a single failed test "
        "will result in the testing never finishing as the tool waits for input.",
    )
    test_parser.add_argument(
        "-d",
        "--detections_list",
        required=False,
        nargs="+",
        default=None,
        type=str,
        help="An explicit list "
        "of detections to test. Their paths should be relative to the app path.",
    )

    test_parser.add_argument("--unattended", action=argparse.BooleanOptionalAction)

    test_parser.add_argument(
        "--infrastructure",
        required=False,
        type=str,
        choices=DetectionTestingTargetInfrastructure._member_names_,
        default=None,
        help=(
            "Determines what infrastructure to use for testing. The options are "
            "container and server.  Container will set up Splunk Container(s) at runtime, "
            "install all relevant apps, and perform configurations.  Server will use "
            "preconfigured server(s) either specified on the command line or in "
            "contentctl_test.yml."
        )
    )
    test_parser.add_argument("--num_containers", required=False, default=1, type=int)
    test_parser.add_argument("--server_info", required=False, default=None, type=str, nargs='+')
    
    test_parser.add_argument("--target_branch", required=False, default=None, type=str)
    test_parser.add_argument("--test_branch", required=False, default=None, type=str)
    test_parser.add_argument("--dry_run", action=argparse.BooleanOptionalAction, help="Used to emit dry_run_config/contentctl_test.yml "\
                             "and dry_run_config/contentctl.yml files.  These are used for CI/CD-driven internal testing workflows and are not intended for public use at this time.")
    
    # Even though these are also options to build, make them available to test_parser
    # as well to make the tool easier to use
    test_parser.add_argument(
        "--splunk_api_username",
        required=False,
        type=str,
        default=None,
        help=(
            f"Username for running AppInspect on {SecurityContentProduct.SPLUNK_APP.name} ONLY. For documentation, "
            "please review https://dev.splunk.com/enterprise/reference/appinspect/appinspectapiepref"
        )
    )
    test_parser.add_argument(
        "--splunk_api_password",
        required=False,
        type=str,
        default=None,
        help=(
            f"Password for running AppInspect on {SecurityContentProduct.SPLUNK_APP.name} ONLY. For documentation, "
            "please review https://dev.splunk.com/enterprise/reference/appinspect/appinspectapiepref"
        )
    )
    test_parser.add_argument(
        "--enable_integration_testing",
        required=False,
        action="store_true",
        help="Whether integration testing should be enabled, in addition to unit testing (requires a configured Splunk "
        "instance with ES installed)"
    )

    # TODO (cmcginley): add flag for enabling logging for correlation_search logging
    # TODO (cmcginley): add flag for changing max_sleep time for integration tests
    # TODO (cmcginley): add setting to skip listing skips -> test_config.TestConfig,
    #   contentctl.test, contentctl.main



    test_parser.set_defaults(func=test)

    convert_parser.add_argument(
        "-dm",
        "--data_model",
        required=False,
        type=str,
        default="cim",
        help="converter target, choose between cim, raw, ocsf"
    )
    convert_parser.add_argument("-lo", "--log_source", required=False, type=str, help="converter log source")
    convert_parser.add_argument("-dp", "--detection_path", required=False, type=str, help="path to a single detection")
    convert_parser.add_argument(
        "-df",
        "--detection_folder",
        required=False,
        type=str,
        help="path to a detection folder"
    )
    convert_parser.add_argument("-o", "--output", required=True, type=str, help="output path to store the detections")
    convert_parser.set_defaults(func=convert)

    release_notes_parser.add_argument("--old_tag", "--old_tag", required=False, type=str, help="Choose the tag and compare with previous tag")
    release_notes_parser.add_argument("--new_tag", "--new_tag", required=False, type=str, help="Choose the tag and compare with previous tag")
    release_notes_parser.add_argument("--latest_branch", "--latest_branch", required=False, type=str, help="Choose the tag and compare with previous tag")
    
    release_notes_parser.set_defaults(func=release_notes)



    # parse them
    args = parser.parse_args()
    

    print_ascii_art()
    try:
        args.func(args)
    except Exception as e:
        print(f"Error during contentctl:\n{str(e)}")
        import traceback
        traceback.print_exc()
        # traceback.print_stack()
        sys.exit(1)
