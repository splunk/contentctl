import argparse
import copy
import io
import json
from bin.detection_testing.modules import jsonschema_errorprinter, constants

import sys
from typing import Union


# If we want, we can easily add a description field to any of the objects here!


def validate_file(file: io.TextIOWrapper) -> Union[dict, None]:
    try:
        settings = json.loads(file.read())
        return validate(settings)
    except Exception as e:
        raise(e)
        


def validate_and_write(configuration: dict, output_file: Union[io.TextIOWrapper, None] = None) -> Union[dict, None]:
    closeFile = False
    if output_file is None:
        import datetime
        now = datetime.datetime.now()
        configname = now.strftime('%Y-%m-%dT%H:%M:%S%z') + '-test-run.json'
        output_file = open(configname, "w")
        closeFile = True

    
    validated_json = validate(configuration)
    if validated_json == None:
        print("Error in the new settings! No output file written")
    else:
        print("Settings updated.  Writing results to: %s" %
              (output_file.name))
        try:
            output_file.write(json.dumps(
                validated_json, sort_keys=True, indent=4))
        except Exception as e:
            print("Error writing settings to %s: [%s]" % (
                output_file.name, str(e)), file=sys.stderr)
            sys.exit(1)
    if closeFile is True:
        output_file.close()

    return validated_json


def validate(configuration: dict) -> Union[dict, None]:
    try:

        validation_errors, validated_json = jsonschema_errorprinter.check_json(configuration, constants.setup_schema)
        if len(validation_errors) == 0:
            return validated_json
            
        else:
            print("[%d] failures detected during validation of the configuration!" % (
                len(validation_errors)), file=sys.stderr)
            for error in validation_errors:
                print(error, end="\n\n", file=sys.stderr)
            return None

    except Exception as e:
        print("There was an error validation the configuration: [%s]" % (
            str(e)), file=sys.stderr)
        return None