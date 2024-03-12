from contentctl.actions.initialize import Initialize
from tyro import cli
from contentctl.objects.config import Config_Base, CustomApp, init, validate, build,  new, deploy_acs, deploy_rest, test, test_servers,deploy_acs_wrapper
from typing import Union
from contentctl.actions.validate import Validate
from contentctl.actions.new_content import NewContent
from contentctl.actions.detection_testing.GitService import GitService
from contentctl.actions.build import (
     BuildInputDto,
     DirectorOutputDto,
     Build,
)
import sys
import pathlib
from contentctl.input.yml_reader import YmlReader

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




def init_func(config:init):    
    Initialize().execute(config)


def validate_func(config:validate):
    validate = Validate()
    return validate.execute(config)


def build_func(config:build)->DirectorOutputDto:
    # First, perform validation. Remember that the validate
    # configuration is actually a subset of the build configuration
    director_output_dto = validate_func(config)
    builder = Build()
    return builder.execute(BuildInputDto(director_output_dto, config))

def new_func(config:new):
    NewContent().execute(config)

def deploy_acs_func(config:deploy_acs_wrapper):
    # Due to the way that the default values are parsed, we need
    # to reparse the deploy_acs values here
    # We use __dict__ rather than model_dump because sensitive values,
    # like password, are set to exclude=True and not serialzied on model_dump
    config_deploy_acs:deploy_acs = deploy_acs.model_validate(config.__dict__)
    raise Exception("deploy acs not yet implemented")

def deploy_rest_func(config:deploy_rest):
    raise Exception("deploy rest not yet implemented")
    

def test_func(config:test):
    director_output_dto = build_func(config)
    
    
    gitServer = GitService(director=director_output_dto,config=config)
    content = gitServer.getContent()
    #test_input_dto = TestInputDto(director_output_dto, gitService, config)
    
    #t = Test()

    #t.execute(test_input_dto)

def test_servers_func(config:test_servers):
    raise Exception("Not yet done")

def main():
    
    
    #try:
    if 1:
        configFile = pathlib.Path("contentctl.yml")
        if not configFile.is_file():
            raise Exception(f"Config File {configFile} does not exist. Please create it with 'contentctl init'")        
        config_obj = YmlReader().load_file(configFile)
        t = test.model_validate(config_obj)
        b = build.model_validate(config_obj)
    #except Exception as e:
    #    print(e)
    #    sys.exit(1)    
    import tyro
    
    '''
    #y = deploy_rest.model_construct(config_obj)
    from typing import Union, Annotated
    config=cli( Union[
        Annotated[init,tyro.conf.subcommand("init", default=t)],
        Annotated[validate,tyro.conf.subcommand("validate", default=t)],
        Annotated[build,tyro.conf.subcommand("build", default=t)],
        #Annotated[new,tyro.conf.subcommand("new",default=new.model_construct(**t.model_dump()))],
        Annotated[test,tyro.conf.subcommand("test", default=t,)],
        Annotated[test_servers,tyro.conf.subcommand("test_servers")],
        Annotated[deploy_acs,tyro.conf.subcommand("deploy_acs")]
        ])
    '''


    models = tyro.extras.subcommand_type_from_defaults(
        {
            "init":init.model_validate(config_obj),
            "validate": validate.model_validate(config_obj),
            "build":build.model_validate(config_obj),
            "new":new.model_validate(config_obj),
            "test":test.model_validate(config_obj),
            "test_servers":test_servers.model_validate(config_obj),
            "deploy_acs": deploy_acs_wrapper.model_validate(config_obj),
            #"deploy_rest":deploy_rest()
        }
    )
        
    #cli(Union[init, validate, build, new, test, test_servers],default=t)
    config = cli(models)
   
    

    
    

    #config = cli(Union[init, validate, build, new, test, test_servers, deploy_acs, deploy_rest])    
    
    
    if type(config) == init:    
        init_func(config)
    if type(config) == validate:
        validate_func(config)
    elif type(config) == build:
        build_func(config)
    elif type(config) == new:
        new_func(config)
    elif type(config) == deploy_acs_wrapper:
        deploy_acs_func(config)
    elif type(config) == deploy_rest:
        deploy_rest_func(config)
    elif type(config) == test:
        test_func(config)
    elif type(config) == test_servers:
        test_servers_func(config)
    