import jsonschema
import hierarchy_schema
import json
import sys
filename = 'folder_hierarchy.json'

root = hierarchy_schema.root
try:
    with open(filename, 'r') as dat:
        json_data = json.load(dat)
except Exception as e:
    print(f"Error loading json data from {filename}: {str(e)}")
    sys.exit(1)
'''
try:
    jsonschema.validate({},schema=root)
except Exception as e:
    print(f"Error parsing schema: {str(e)}")
    sys.exit(1)
'''

try:
    jsonschema.validate(json_data, schema=root)
except Exception as e:
    print(f"Error validating json scehma for {filename}: {str(e)}")
    sys.exit(1)

print("Validation successful!")
sys.exit(0)