import sys
import argparse
import os

import yaml

from contentctl.actions.detection_testing.GitHubService import (
    GithubService,
)
from contentctl.actions.validate import ValidateInputDto, Validate
from contentctl.actions.generate import (
    GenerateInputDto,
    DirectorOutputDto,
    Generate,
)
from contentctl.actions.reporting import ReportingInputDto, Reporting
from contentctl.actions.new_content import NewContentInputDto, NewContent
from contentctl.actions.doc_gen import DocGenInputDto, DocGen
from contentctl.actions.initialize import Initialize, InitializeInputDto
from contentctl.actions.deploy import Deploy, DeployInputDto
from contentctl.input.director import DirectorInputDto
from contentctl.objects.enums import (
    SecurityContentType,
    SecurityContentProduct,
    DetectionTestingMode,
    PostTestBehavior,
)
from contentctl.input.new_content_generator import NewContentGeneratorInputDto
from contentctl.helper.config_handler import ConfigHandler

from contentctl.objects.config import Config

from contentctl.objects.app import App
from contentctl.objects.test_config import TestConfig
from contentctl.actions.test import Test, TestInputDto, TestOutputDto


import tqdm
import functools


def configure_unattended(args: argparse.Namespace) -> argparse.Namespace:
    # disable all calls to tqdm - this is so that CI/CD contexts don't
    # have a large amount of output due to progress bar updates.
    tqdm.tqdm.__init__ = functools.partialmethod(
        tqdm.tqdm.__init__, disable=args.unattended
    )
    if args.unattended:
        if args.behavior != PostTestBehavior.never_pause.name:
            print(
                f"For unattended mode, --behavior MUST be {PostTestBehavior.never_pause.name}.\nUpdating the behavior from '{args.behavior}' to '{PostTestBehavior.never_pause.name}'"
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


def start(args) -> Config:
    return ConfigHandler.read_config(os.path.join(args.path, "contentctl.yml"))


def initialize(args) -> None:

    Initialize().execute(InitializeInputDto(path=os.path.abspath(args.path)))


def build(args) -> DirectorOutputDto:
    config = start(args)
    product_type = SecurityContentProduct.splunk_app
    director_input_dto = DirectorInputDto(
        input_path=os.path.abspath(args.path), product=product_type, config=config
    )
    generate_input_dto = GenerateInputDto(director_input_dto)

    generate = Generate()

    return generate.execute(generate_input_dto)


def inspect(args) -> None:
    raise (Exception("WARNING - INSPECT NOT YET IMPLEMENTED"))
    # Inspect(args)


def deploy(args) -> None:
    config = start(args)
    deploy_input_dto = DeployInputDto(path=args.path, config=config)
    deploy = Deploy()
    deploy.execute(deploy_input_dto)


def test(args: argparse.Namespace):
    args = configure_unattended(args)
    config = start(args)

    # set some arguments that are not
    # yet exposed/written properly in
    # the config file
    test_config = TestConfig.parse_obj(
        {
            # "repo_path": args.path,
            "mode": args.mode,
            "num_containers": 1,
            "post_test_behavior": args.behavior,
            "detections_list": args.detections_list,
        }
    )

    # We do this before generating the app to save some time if options are incorrect.
    # For example, if the detection(s) we are trying to test do not exist
    githubService = GithubService(test_config)

    director_output_dto = build(args)

    # All this information will later come from the config, so we will
    # be able to do it in Test().execute. For now, we will do it here
    app = App(
        uid=9999,
        appid="my_custom_app",
        title="my_custom_app",
        release="1.0.0",
        http_path=None,
        local_path=os.path.join(
            os.path.abspath(args.path), f"{config.build.splunk_app.path}.tar.gz"
        ),
        description="some description",
        splunkbase_path=None,
    )

    # We need to do this instead of appending to retrigger validation.
    # It does not happen the first time since validation does not run for default values
    # unless we use always=True in the validator
    # we always want to keep CIM as the last app installed

    test_config.apps = [app] + test_config.apps

    test_input_dto = TestInputDto(
        director_output_dto=director_output_dto,
        githubService=githubService,
        config=test_config,
    )
    test = Test()

    try:
        result = test.execute(test_input_dto)
        # This return code is important.  Even if testing
        # fully completes, if everything does not pass then
        # we want to return a nonzero status code
        if result:
            sys.exit(0)
        else:
            sys.exit(1)

    except Exception as e:
        print("Error running contentctl test: {str(e)}")
        sys.exit(1)


def validate(args) -> None:
    config = start(args)
    product_type = SecurityContentProduct.splunk_app
    director_input_dto = DirectorInputDto(
        input_path=os.path.abspath(args.path), product=product_type, config=config
    )
    validate_input_dto = ValidateInputDto(director_input_dto=director_input_dto)
    validate = Validate()
    return validate.execute(validate_input_dto)


def doc_gen(args) -> None:
    config = start(args)
    director_input_dto = DirectorInputDto(
        input_path=args.path, product=SecurityContentProduct.splunk_app, config=config
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
        input_path=args.path, product=SecurityContentProduct.splunk_app, config=config
    )

    reporting_input_dto = ReportingInputDto(director_input_dto=director_input_dto)

    reporting = Reporting()
    reporting.execute(reporting_input_dto)


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
    new_content_parser = actions_parser.add_parser(
        "new", help="create new Splunk content object (detection, or story)"
    )
    reporting_parser = actions_parser.add_parser(
        "report", help="create Splunk content report of the current pack"
    )
    inspect_parser = actions_parser.add_parser(
        "inspect",
        help="runs Splunk appinspect on a build Splunk app to ensure that an app meets Splunkbase requirements.",
    )
    deploy_parser = actions_parser.add_parser(
        "deploy", help="install an application on a target Splunk instance."
    )
    docs_parser = actions_parser.add_parser(
        "docs", help="create documentation in docs folder"
    )

    test_parser = actions_parser.add_parser(
        "test",
        help="Run a test of the detections against a Splunk Server or Splunk Docker Container",
    )

    init_parser.set_defaults(func=initialize)

    validate_parser.set_defaults(func=validate)

    build_parser.set_defaults(func=build)

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

    inspect_parser.add_argument(
        "-ap",
        "--app_path",
        required=False,
        type=str,
        default=None,
        help="path to the Splunk app to be inspected",
    )
    inspect_parser.set_defaults(func=inspect)

    deploy_parser.set_defaults(func=deploy)

    test_parser.add_argument(
        "--mode",
        required=False,
        default=DetectionTestingMode.all.name,
        type=str,
        choices=DetectionTestingMode._member_names_,
        help="Controls which detections to test. 'all' will test all detections in the repo."
        "'selected' will test a list of detections that have "
        "been provided via the --selected command line argument (see for more details).",
    )
    test_parser.add_argument(
        "--behavior",
        required=False,
        default=PostTestBehavior.pause_on_failure.name,
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
        type=str,
        help="An explicit list "
        "of detections to test. Their paths should be relative to the app path.",
    )

    test_parser.add_argument("--unattended", action=argparse.BooleanOptionalAction)

    test_parser.set_defaults(func=test)

    # parse them
    args = parser.parse_args()

    print_ascii_art()
    args.func(args)
