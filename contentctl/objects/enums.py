from __future__ import annotations
from typing import List
import enum


class AnalyticsType(str, enum.Enum):
    TTP = "TTP"
    Anomaly = "Anomaly"
    Hunting = "Hunting"
    Correlation = "Correlation"

class DeploymentType(str, enum.Enum):
    TTP = "TTP"
    Anomaly = "Anomaly"
    Hunting = "Hunting"
    Correlation = "Correlation"
    Baseline = "Baseline"
    Embedded = "Embedded"


class DataModel(str,enum.Enum):
    ENDPOINT = "Endpoint"
    NETWORK_TRAFFIC  = "Network_Traffic"
    AUTHENTICATION = "Authentication"
    CHANGE = "Change"
    CHANGE_ANALYSIS = "Change_Analysis"
    EMAIL = "Email"
    NETWORK_RESOLUTION = "Network_Resolution"
    NETWORK_SESSIONS = "Network_Sessions"
    UEBA = "UEBA"
    UPDATES = "Updates"
    VULNERABILITIES = "Vulnerabilities"
    WEB = "Web"
    #Should the following more specific DMs be added? 
    #Or should they just fall under endpoint?
    #ENDPOINT_PROCESSES = "Endpoint_Processes"
    #ENDPOINT_FILESYSTEM = "Endpoint_Filesystem"
    #ENDPOINT_REGISTRY = "Endpoint_Registry"
    RISK = "Risk"
    SPLUNK_AUDIT = "Splunk_Audit"


class PlaybookType(str, enum.Enum):
    INVESTIGATION = "Investigation"
    RESPONSE = "Response"

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
    ssa_detections = 10
    data_sources = 11

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


class SecurityContentProductName(str, enum.Enum):
    SPLUNK_ENTERPRISE = "Splunk Enterprise"
    SPLUNK_ENTERPRISE_SECURITY = "Splunk Enterprise Security"
    SPLUNK_CLOUD = "Splunk Cloud"
    SPLUNK_SECURITY_ANALYTICS_FOR_AWS = "Splunk Security Analytics for AWS"
    SPLUNK_BEHAVIORAL_ANALYTICS = "Splunk Behavioral Analytics"

class SecurityContentInvestigationProductName(str, enum.Enum):
    SPLUNK_ENTERPRISE = "Splunk Enterprise"
    SPLUNK_ENTERPRISE_SECURITY = "Splunk Enterprise Security"
    SPLUNK_CLOUD = "Splunk Cloud"
    SPLUNK_SECURITY_ANALYTICS_FOR_AWS = "Splunk Security Analytics for AWS"
    SPLUNK_BEHAVIORAL_ANALYTICS = "Splunk Behavioral Analytics"
    SPLUNK_PHANTOM = "Splunk Phantom"
    

class DetectionStatus(enum.Enum):
    production = "production"
    deprecated = "deprecated"
    experimental = "experimental"
    validation = "validation"


class DetectionStatusSSA(enum.Enum):
    production = "production"
    deprecated = "deprecated"
    experimental = "experimental"
    validation = "validation"


class LogLevel(enum.Enum):
    NONE = "NONE"
    ERROR = "ERROR"
    INFO = "INFO"


class AlertActions(enum.Enum):
    notable = "notable"
    rba = "rba"
    email = "email"


class StoryCategory(str, enum.Enum):
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
    PRIVILEGE_ESCALATION = "Privilege Escalation"
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


class SigmaConverterTarget(enum.Enum):
    CIM = 1
    RAW = 2
    OCSF = 3
    ALL = 4

# It's unclear why we use a mix of constants and enums. The following list was taken from:
# contentctl/contentctl/helper/constants.py.
# We convect it to an enum here
# SES_KILL_CHAIN_MAPPINGS = {
#     "Unknown": 0,
#     "Reconnaissance": 1,
#     "Weaponization": 2,
#     "Delivery": 3,
#     "Exploitation": 4,
#     "Installation": 5,
#     "Command And Control": 6,
#     "Actions on Objectives": 7
# }
class KillChainPhase(str, enum.Enum):
    UNKNOWN ="Unknown"
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITAITON = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command and Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"


class DataSource(str,enum.Enum):
    OSQUERY_ES_PROCESS_EVENTS = "OSQuery ES Process Events"
    POWERSHELL_4104 = "Powershell 4104"
    SYSMON_EVENT_ID_1 = "Sysmon Event ID 1"
    SYSMON_EVENT_ID_10 = "Sysmon Event ID 10"
    SYSMON_EVENT_ID_11 = "Sysmon Event ID 11"
    SYSMON_EVENT_ID_13 = "Sysmon Event ID 13"
    SYSMON_EVENT_ID_15 = "Sysmon Event ID 15"
    SYSMON_EVENT_ID_20 = "Sysmon Event ID 20"
    SYSMON_EVENT_ID_21 = "Sysmon Event ID 21"
    SYSMON_EVENT_ID_22 = "Sysmon Event ID 22"
    SYSMON_EVENT_ID_23 = "Sysmon Event ID 23"
    SYSMON_EVENT_ID_3 = "Sysmon Event ID 3"
    SYSMON_EVENT_ID_5 = "Sysmon Event ID 5"
    SYSMON_EVENT_ID_6 = "Sysmon Event ID 6"
    SYSMON_EVENT_ID_7 = "Sysmon Event ID 7"
    SYSMON_EVENT_ID_8 = "Sysmon Event ID 8"
    SYSMON_EVENT_ID_9 = "Sysmon Event ID 9"
    WINDOWS_SECURITY_4624 = "Windows Security 4624"
    WINDOWS_SECURITY_4625 = "Windows Security 4625"
    WINDOWS_SECURITY_4648 = "Windows Security 4648"
    WINDOWS_SECURITY_4663 = "Windows Security 4663"
    WINDOWS_SECURITY_4688 = "Windows Security 4688"
    WINDOWS_SECURITY_4698 = "Windows Security 4698"
    WINDOWS_SECURITY_4703 = "Windows Security 4703"
    WINDOWS_SECURITY_4720 = "Windows Security 4720"
    WINDOWS_SECURITY_4732 = "Windows Security 4732"
    WINDOWS_SECURITY_4738 = "Windows Security 4738"
    WINDOWS_SECURITY_4741 = "Windows Security 4741"
    WINDOWS_SECURITY_4742 = "Windows Security 4742"
    WINDOWS_SECURITY_4768 = "Windows Security 4768"
    WINDOWS_SECURITY_4769 = "Windows Security 4769"
    WINDOWS_SECURITY_4771 = "Windows Security 4771"
    WINDOWS_SECURITY_4776 = "Windows Security 4776"
    WINDOWS_SECURITY_4781 = "Windows Security 4781"
    WINDOWS_SECURITY_4798 = "Windows Security 4798"
    WINDOWS_SECURITY_5136 = "Windows Security 5136"
    WINDOWS_SECURITY_5145 = "Windows Security 5145"
    WINDOWS_SYSTEM_7045 = "Windows System 7045"

class ProvidingTechnology(str, enum.Enum):
    AMAZON_SECURITY_LAKE = "Amazon Security Lake"
    AMAZON_WEB_SERVICES_CLOUDTRAIL = "Amazon Web Services - Cloudtrail"
    AZURE_AD = "Azure AD"
    CARBON_BLACK_RESPONSE = "Carbon Black Response"
    CROWDSTRIKE_FALCON = "CrowdStrike Falcon"
    ENTRA_ID = "Entra ID"
    GOOGLE_CLOUD_PLATFORM = "Google Cloud Platform"
    GOOGLE_WORKSPACE = "Google Workspace"
    KUBERNETES = "Kubernetes"
    MICROSOFT_DEFENDER = "Microsoft Defender"
    MICROSOFT_OFFICE_365 = "Microsoft Office 365"
    MICROSOFT_SYSMON = "Microsoft Sysmon"
    MICROSOFT_WINDOWS = "Microsoft Windows"
    OKTA = "Okta"
    PING_ID = "Ping ID"
    SPLUNK_INTERNAL_LOGS = "Splunk Internal Logs"
    SYMANTEC_ENDPOINT_PROTECTION = "Symantec Endpoint Protection"
    ZEEK = "Zeek"
    
    @staticmethod
    def getProvidingTechFromSearch(search_string:str)->List[ProvidingTechnology]:
        """_summary_

        Args:
            search_string (str): The search string to extract the providing technologies from.
            The providing_technologies_mapping provides keywords, macros, etc that can be updated
            with new mappings.  If that substring appears in the search, then its list of providing
            technologies is added.

        Returns:
            List[ProvidingTechnology]: List of providing technologies (with no duplicates because
            it is derived from a set) calculated from the search string.
        """        
        matched_technologies:set[ProvidingTechnology] = set()
        #As there are many different sources that use google logs, we define the set once
        google_logs = set([ProvidingTechnology.GOOGLE_WORKSPACE, ProvidingTechnology.GOOGLE_CLOUD_PLATFORM])
        providing_technologies_mapping = {
            '`amazon_security_lake`': set([ProvidingTechnology.AMAZON_SECURITY_LAKE]),
            'audit_searches': set([ProvidingTechnology.SPLUNK_INTERNAL_LOGS]),
            '`azure_monitor_aad`': set([ProvidingTechnology.AZURE_AD, ProvidingTechnology.ENTRA_ID]),
            '`cloudtrail`': set([ProvidingTechnology.AMAZON_WEB_SERVICES_CLOUDTRAIL]),
            #Endpoint is NOT a Macro (and this is intentional since it is to capture Endpoint Datamodel usage)
            'Endpoint': set([ProvidingTechnology.MICROSOFT_SYSMON, 
                             ProvidingTechnology.MICROSOFT_WINDOWS,
                             ProvidingTechnology.CARBON_BLACK_RESPONSE,
                             ProvidingTechnology.CROWDSTRIKE_FALCON, 
                             ProvidingTechnology.SYMANTEC_ENDPOINT_PROTECTION]),
            '`google_': google_logs,
            '`gsuite': google_logs,
            '`gws_': google_logs,
            '`kube': set([ProvidingTechnology.KUBERNETES]),
            '`ms_defender`': set([ProvidingTechnology.MICROSOFT_DEFENDER]),
            '`o365_': set([ProvidingTechnology.MICROSOFT_OFFICE_365]),
            '`okta': set([ProvidingTechnology.OKTA]),
            '`pingid`': set([ProvidingTechnology.PING_ID]),
            '`powershell`': set(set([ProvidingTechnology.MICROSOFT_WINDOWS])),
            '`splunkd_': set([ProvidingTechnology.SPLUNK_INTERNAL_LOGS]),
            '`sysmon`': set([ProvidingTechnology.MICROSOFT_SYSMON]),
            '`wineventlog_security`': set([ProvidingTechnology.MICROSOFT_WINDOWS]),
            '`zeek_': set([ProvidingTechnology.ZEEK]),
        }
        for key in providing_technologies_mapping:
            if key in search_string:
                matched_technologies.update(providing_technologies_mapping[key])
        return sorted(list(matched_technologies))


class Cis18Value(str,enum.Enum):
    CIS_0 = "CIS 0"
    CIS_1 = "CIS 1"
    CIS_2 = "CIS 2"
    CIS_3 = "CIS 3"
    CIS_4 = "CIS 4"
    CIS_5 = "CIS 5"
    CIS_6 = "CIS 6"
    CIS_7 = "CIS 7"
    CIS_8 = "CIS 8"
    CIS_9 = "CIS 9"
    CIS_10 = "CIS 10"
    CIS_11 = "CIS 11"
    CIS_12 = "CIS 12"
    CIS_13 = "CIS 13"
    CIS_14 = "CIS 14"
    CIS_15 = "CIS 15"
    CIS_16 = "CIS 16"
    CIS_17 = "CIS 17"
    CIS_18 = "CIS 18"

class SecurityDomain(str, enum.Enum):
    ENDPOINT = "endpoint"
    NETWORK = "network"
    THREAT = "threat"
    IDENTITY = "identity"
    ACCESS = "access"
    AUDIT = "audit"
    CLOUD = "cloud"

class AssetType(str, enum.Enum):
    AWS_ACCOUNT = "AWS Account"
    AWS_EKS_KUBERNETES_CLUSTER = "AWS EKS Kubernetes cluster"
    AWS_FEDERATED_ACCOUNT = "AWS Federated Account"
    AWS_INSTANCE = "AWS Instance"
    ACCOUNT = "Account"
    AMAZON_EKS_KUBERNETES_CLUSTER = "Amazon EKS Kubernetes cluster"
    AMAZON_EKS_KUBERNETES_CLUSTER_POD = "Amazon EKS Kubernetes cluster Pod"
    AMAZON_ELASTIC_CONTAINER_REGISTRY = "Amazon Elastic Container Registry"
    #AZURE = "Azure"
    #AZURE_AD = "Azure AD"
    #AZURE_AD_TENANT = "Azure AD Tenant"
    AZURE_TENANT = "Azure Tenant"
    AZURE_AKS_KUBERNETES_CLUSTER = "Azure AKS Kubernetes cluster"
    AZURE_ACTIVE_DIRECTORY = "Azure Active Directory"
    CIRCLECI = "CircleCI"
    CLOUD_COMPUTE_INSTANCE = "Cloud Compute Instance"
    CLOUD_INSTANCE = "Cloud Instance"
    DNS_SERVERS = "DNS Servers"
    DATABASE_SERVER = "Database Server"
    DOMAIN_SERVER = "Domain Server"
    EC2_SNAPSHOT = "EC2 Snapshot"
    ENDPOINT = "Endpoint"
    GCP = "GCP"
    GCP_ACCOUNT = "GCP Account"
    GCP_GKE_EKS_KUBERNETES_CLUSTER = "GCP GKE EKS Kubernetes cluster"
    GCP_GKE_KUBERNETES_CLUSTER = "GCP GKE Kubernetes cluster"
    GCP_KUBERNETES_CLUSTER = "GCP Kubernetes cluster"
    GCP_STORAGE_BUCKET = "GCP Storage Bucket"
    GDRIVE = "GDrive"
    GSUITE = "GSuite"
    GITHUB = "GitHub"
    GOOGLE_CLOUD_PLATFORM_TENANT = "Google Cloud Platform tenant"
    IDENTITY = "Identity"
    INFRASTRUCTURE = "Infrastructure"
    INSTANCE = "Instance"
    KUBERNETES = "Kubernetes"
    NETWORK = "Network"
    #OFFICE_365 = "Office 365"
    #OFFICE_365_Tenant = "Office 365 Tenant"
    O365_TENANT = "O365 Tenant"
    OKTA_TENANT = "Okta Tenant"
    PROXY = "Proxy"
    S3_BUCKET = "S3 Bucket"
    SPLUNK_SERVER = "Splunk Server"
    VPN_Appliance = "VPN Appliance"
    WEB_SERVER = "Web Server"
    WEB_PROXY = "Web Proxy"
    WEB_APPLICATION = "Web Application"
    WINDOWS = "Windows"

class NistCategory(str, enum.Enum):
    ID_AM = "ID.AM"
    ID_BE = "ID.BE"
    ID_GV = "ID.GV"
    ID_RA = "ID.RA"
    ID_RM = "ID.RM"
    PR_AC = "PR.AC"
    PR_AT = "PR.AT"
    PR_DS = "PR.DS"
    PR_IP = "PR.IP"
    PR_MA = "PR.MA"
    PR_PT = "PR.PT"
    DE_AE = "DE.AE"
    DE_CM = "DE.CM"
    DE_DP = "DE.DP"
    RS_RP = "RS.RP"
    RS_CO = "RS.CO"
    RS_AN = "RS.AN"
    RS_MI = "RS.MI"
    RS_IM = "RS.IM"
    RC_RP = "RC.RP"
    RC_IM = "RC.IM"
    RC_CO = "RC.CO"

class RiskLevel(str,enum.Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class RiskSeverity(str,enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
