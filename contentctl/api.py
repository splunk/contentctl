from pathlib import Path
from typing import Any, Union, Type
from contentctl.input.yml_reader import YmlReader
from contentctl.objects.config import test_common, test, test_servers
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.input.director import DirectorOutputDto

def config_from_file(path:Path=Path("contentctl.yml"), config: dict[str,Any]={}, 
                   configType:Type[Union[test,test_servers]]=test)->test_common:
    
    """
    Fetch a configuration object that can be used for a number of different contentctl
    operations including validate, build, inspect, test, and test_servers. A file will 
    be used as the basis for constructing the configuration.

    Args:
        path (Path, optional): Relative or absolute path to a contentctl config file. 
        Defaults to Path("contentctl.yml"), which is the default name and location (in the current directory)
        of the configuration files which are automatically generated for contentctl.
        config (dict[], optional): Dictionary of values to override values read from the YML
        path passed as the first argument. Defaults to {}, an empty dict meaning that nothing
        will be overwritten 
        configType (Type[Union[test,test_servers]], optional): The Config Class to instantiate. 
        This may be a test or test_servers object. Note that this is NOT an instance of the class. Defaults to test.
    Returns:
        test_common: Returns a complete contentctl test_common configuration. Note that this configuration
        will have all applicable field for validate and build as well, but can also be used for easily
        construction a test or test_servers object.  
    """    

    try:
        yml_dict = YmlReader.load_file(path, add_fields=False)
        
        
    except Exception as e:
        raise Exception(f"Failed to load contentctl configuration from file '{path}': {str(e)}")
    
    # Apply settings that have been overridden from the ones in the file
    try:
        yml_dict.update(config)
    except Exception as e:
        raise Exception(f"Failed updating dictionary of values read from file '{path}'"
                        f" with the dictionary of arguments passed: {str(e)}")

    # The function below will throw its own descriptive exception if it fails
    configObject = config_from_dict(yml_dict, configType=configType)

    return configObject




def config_from_dict(config: dict[str,Any]={}, 
                   configType:Type[Union[test,test_servers]]=test)->test_common:
    """
    Fetch a configuration object that can be used for a number of different contentctl
    operations including validate, build, inspect, test, and test_servers. A dict will 
    be used as the basis for constructing the configuration.

    Args:
        config (dict[str,Any],Optional): If a dictionary is not explicitly passed, then
        an empty dict will be used to create a configuration, if possible, from default
        values.  Note that based on default values in the contentctl/objects/config.py
        file, this may raise an exception.  If so, please set appropriate default values
        in the file above or supply those values via this argument.
        configType (Type[Union[test,test_servers]], optional): The Config Class to instantiate. 
        This may be a test or test_servers object. Note that this is NOT an instance of the class. Defaults to test.
    Returns:
        test_common: Returns a complete contentctl test_common configuration. Note that this configuration
        will have all applicable field for validate and build as well, but can also be used for easily
        construction a test or test_servers object.  
    """    
    try:
        test_object = configType.model_validate(config)
    except Exception as e:
        raise Exception(f"Failed to load contentctl configuration from dict:\n{str(e)}")
    
    return test_object


def update_config(config:Union[test,test_servers], **key_value_updates:dict[str,Any])->test_common:
    
    """Update any relevant keys in a config file with the specified values.
    Full validation will be performed after this update and descriptive errors
    will be produced

    Args:
        config (test_common): A previously-constructed test_common object.  This can be 
        build using the configFromDict or configFromFile functions.
        key_value_updates (kwargs, optional): Additional keyword/argument pairs to update
        arbitrary fields in the configuration.

    Returns:
        test_common: A validated object which has had the relevant fields updated.
        Note that descriptive Exceptions will be generated if updated values are either
        invalid (have the wrong type, or disallowed values) or you attempt to update
        fields that do not exist
    """
    # Create a copy so we don't change the underlying model
    config_copy = config.model_copy(deep=True)

    # Force validation of assignment since doing so via arbitrary dict can be error prone
    # Also, ensure that we do not try to add fields that are not part of the model
    config_copy.model_config.update({'validate_assignment': True, 'extra': 'forbid'})

    
    
    # Collect any errors that may occur
    errors:list[Exception] = []
    
    # We need to do this one by one because the extra:forbid argument does not appear to 
    # be respected at this time.
    for key, value in key_value_updates.items():
        try:
            setattr(config_copy,key,value)
        except Exception as e:
            errors.append(e)
    if len(errors) > 0:
        errors_string = '\n'.join([str(e) for e in errors])
        raise Exception(f"Error(s) updaitng configuration:\n{errors_string}")
    
    return config_copy
    


def content_to_dict(director:DirectorOutputDto)->dict[str,list[dict[str,Any]]]:
    output_dict:dict[str,list[dict[str,Any]]] = {}
    for contentType in ['detections','stories','baselines','investigations',
                        'playbooks','macros','lookups','deployments','ssa_detections']:
        
        output_dict[contentType] = []
        t:list[SecurityContentObject] = getattr(director,contentType)
        
        for item in t:
            output_dict[contentType].append(item.model_dump())
    return output_dict
            
