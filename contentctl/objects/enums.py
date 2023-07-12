import enum


class AnalyticsType(enum.Enum):
    TTP = 1
    anomaly = 2
    hunting = 3
    correlation = 4


class DataModel(enum.Enum):
    Endpoint = 1
    Network_Traffic = 2
    Authentication = 3
    Change = 4
    Change_Analysis = 5
    Email = 6
    Network_Resolution = 7
    Network_Sessions = 8
    UEBA = 9
    Updates = 10
    Vulnerabilities = 11
    Web = 12
    Endpoint_Processes = 13
    Endpoint_Filesystem = 14
    Endpoint_Registry = 15
    Risk = 16
    Splunk_Audit = 17


class SecurityContentType(enum.Enum):
    detections = 1
    baselines = 2
    stories = 3
    playbooks = 4
    macros = 5
    lookups = 6
    deployments = 7
    investigations = 8
    unit_tests = 9

# Bringing these changes back in line will take some time after
# the initial merge is complete
# class SecurityContentProduct(enum.Enum):
#     # This covers ESCU as well as other apps initialized
#     # by splunk_security_content_builder
#     splunk_app = "splunk_app"
#     ba_objects = "ba_objects"
#     json_objects = "json_objects"
class SecurityContentProduct(enum.Enum):
    SPLUNK_APP = 1
    SSA = 2
    API = 3
    CUSTOM = 4

class SigmaConverterTarget(enum.Enum):
    CIM = 1
    RAW = 2
    OCSF = 3
    ALL = 4

class DetectionStatus(enum.Enum):
    production = "production"
    deprecated = "deprecated"
    experimental = "experimental"

class LogLevel(enum.Enum):
    NONE = "NONE"
    ERROR = "ERROR"
    INFO = "INFO"


class AlertActions(enum.Enum):
    notable = "notable"
    rba = "rba"
    email = "email"

class StoryCategory(str,enum.Enum):
    ABUSE = "Abuse"
    ADVERSARY_TACTICS = "Adversary Tactics"
    BEST_PRACTICES = "Best Practices"
    CLOUD_SECURITY = "Cloud Security"
    COMPLIANCE = "Compliance"
    MALWARE = "Malware"
    UNCATEGORIZED = "Uncategorized"
    VULNERABILITY = "Vulnerability"
    

    # The following categories are currently used in
    # security_content stories but do not appear
    # to have mappings in the current version of ES
    # Should they be removed and the stories which
    # reference them updated?
    ACCOUNT_COMPROMSE = "Account Compromise"
    DATA_DESTRUCTION = "Data Destruction"
    LATERAL_MOVEMENT = "Lateral Movement"
    PRIVILEGE_ESCALATION  = "Privilege Escalation"
    RANSOMWARE = "Ransomware"
    UNAUTHORIZED_SOFTWARE = "Unauthorized Software"
  
  

class PostTestBehavior(str, enum.Enum):
    always_pause = "always_pause"
    pause_on_failure = "pause_on_failure"
    never_pause = "never_pause"


class DetectionTestingMode(str, enum.Enum):
    selected = "selected"
    all = "all"
    changes = "changes"


class DetectionTestingTargetInfrastructure(str, enum.Enum):
    container = "container"
    server = "server"


class InstanceState(str, enum.Enum):
    starting = "starting"
    running = "running"
    error = "error"
    stopping = "stopping"
    stopped = "stopped"

