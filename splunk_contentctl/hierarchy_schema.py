
json_root_schema = {
    "$id": "/schemas/root",

    "type": "object",
    "properties": {
        "questions": {
            "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {
                                "type": "string"
                            },
                            "message": {
                                "type": "string"
                            },
                            "name": {
                                "type": "string"
                            },
                            "default": {
                                "type": "string"
                            },
                            "jsonschema_validator": {
                                "type": "object",
                                "properties": {
                                    "type": {
                                        "type": "string",
                                    },
                                    "pattern": {
                                        "type": "string"
                                    }
                                }
                            }

                        },
                        "required": ["type", "message", "name", "default"]
                    }
        },
        "apps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "uid": {
                        "type":"string"
                    },
                    "appid": {
                        "type":"string"
                    },
                    "title": {
                        "type":"string"
                    },
                    "description": {
                        "type":"string"
                    },
                    "description": {
                        "type":"string"
                    },
                    "release": {
                        "type": "string"
                        }
                    }
                }
            }
        },
        "hierarchy": {

            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "required": ["type", "name", "description", "required", "mode", "children"],
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["folder", "file", "template"]
                        },
                        "name": {
                            "type": "string"
                        },
                        "target_name": {
                            "type": "string",
                        },
                        "description": {
                            "type": "string"
                        },
                        "required": {
                            "type": "boolean",
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["copy", "create"]
                        },
                        "children": {
                            "type": "array",
                            "items": {
                                "$ref": "#"
                            }
                        }
                    }
                }
            ]
        }
    }
}
