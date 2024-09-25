# Use for calculation of maximum length of name field
from contentctl.objects.enums import SecurityDomain

ATTACK_TACTICS_KILLCHAIN_MAPPING = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Weaponization",
    "Initial Access": "Delivery",
    "Execution": "Installation",
    "Persistence": "Installation",
    "Privilege Escalation": "Exploitation",
    "Defense Evasion": "Exploitation",
    "Credential Access": "Exploitation",
    "Discovery": "Exploitation",
    "Lateral Movement": "Exploitation",
    "Collection": "Exploitation",
    "Command And Control": "Command and Control",
    "Exfiltration": "Actions on Objectives",
    "Impact": "Actions on Objectives"
}

SES_CONTEXT_MAPPING = {
    "Unknown": 0,
    "Source:Endpoint": 10,
    "Source:AD": 11,
    "Source:Firewall": 12,
    "Source:Application Log": 13,
    "Source:IPS": 14,
    "Source:Cloud Data": 15,
    "Source:Correlation": 16,
    "Source:Printer": 17,
    "Source:Badge": 18,
    "Scope:Internal": 20,
    "Scope:External": 21,
    "Scope:Inbound": 22,
    "Scope:Outbound": 23,
    "Scope:Local": 24,
    "Scope:Network": 25,
    "Outcome:Blocked": 30,
    "Outcome:Allowed": 31,
    "Stage:Recon": 40,
    "Stage:Initial Access": 41,
    "Stage:Execution": 42,
    "Stage:Persistence": 43,
    "Stage:Privilege Escalation": 44,
    "Stage:Defense Evasion": 45,
    "Stage:Credential Access": 46,
    "Stage:Discovery": 47,
    "Stage:Lateral Movement": 48,
    "Stage:Collection": 49,
    "Stage:Exfiltration": 50,
    "Stage:Command And Control": 51,
    "Consequence:Infection": 60,
    "Consequence:Reduced Visibility": 61,
    "Consequence:Data Destruction": 62,
    "Consequence:Denial Of Service": 63,
    "Consequence:Loss Of Control": 64,
    "Rares:Rare User": 70,
    "Rares:Rare Process": 71,
    "Rares:Rare Device": 72,
    "Rares:Rare Domain": 73,
    "Rares:Rare Network": 74,
    "Rares:Rare Location": 75,
    "Other:Peer Group": 80,
    "Other:Brute Force": 81,
    "Other:Policy Violation": 82,
    "Other:Threat Intelligence": 83,
    "Other:Flight Risk": 84,
    "Other:Removable Storage": 85
}

SES_KILL_CHAIN_MAPPINGS = {
    "Unknown": 0,
    "Reconnaissance": 1,
    "Weaponization": 2,
    "Delivery": 3,
    "Exploitation": 4,
    "Installation": 5,
    "Command and Control": 6,
    "Actions on Objectives": 7
}

SES_OBSERVABLE_ROLE_MAPPING = {
    "Other": -1,
    "Unknown": 0,
    "Actor": 1,
    "Target": 2,
    "Attacker": 3,
    "Victim": 4,
    "Parent Process": 5,
    "Child Process": 6,
    "Known Bad": 7,
    "Data Loss": 8,
    "Observer": 9
}

SES_OBSERVABLE_TYPE_MAPPING = {
    "Unknown": 0,
    "Hostname": 1,
    "IP Address": 2,
    "MAC Address": 3,
    "User Name": 4,
    "Email Address": 5,
    "URL String": 6,
    "File Name": 7,
    "File Hash": 8,
    "Process Name": 9,
    "Resource UID": 10,
    "Endpoint": 20,
    "User": 21,
    "Email": 22,
    "Uniform Resource Locator": 23,
    "File": 24,
    "Process": 25,
    "Geo Location": 26,
    "Container": 27,
    "Registry Key": 28,
    "Registry Value": 29,
    "Other": 99
}

SES_ATTACK_TACTICS_ID_MAPPING = {
    "Reconnaissance": "TA0043",
    "Resource_Development": "TA0042",
    "Initial_Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege_Escalation": "TA0004",
    "Defense_Evasion": "TA0005",
    "Credential_Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral_Movement": "TA0008",
    "Collection": "TA0009",
    "Command_and_Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040"
}

RBA_OBSERVABLE_ROLE_MAPPING = {
    "Attacker": 0,
    "Victim": 1
}

# The relative path to the directory where any apps/packages will be downloaded
DOWNLOADS_DIRECTORY = "downloads"

# Maximum length of the name field for a search.
# This number is derived from a limitation that exists in 
# ESCU where a search cannot be edited, due to validation
# errors, if its name is longer than 99 characters.
# When an saved search is cloned in Enterprise Security User Interface,
# it is wrapped in the following: 
# {Detection.tags.security_domain.value} - {SEARCH_STANZA_NAME} - Rule
# Similarly, when we generate the search stanza name in contentctl, it
# is app.label - detection.name - Rule
# However, in product the search name is:
# {CustomApp.label} - {detection.name} - Rule,
# or in ESCU:
# ESCU - {detection.name} - Rule,
# this gives us a maximum length below.
# When an ESCU search is cloned, it will 
# have a full name like (the following is NOT a typo):
# Endpoint - ESCU - Name of Search From YML File - Rule - Rule
# The math below accounts for all these caveats
ES_MAX_STANZA_LENGTH = 99
CONTENTCTL_DETECTION_STANZA_NAME_FORMAT_TEMPLATE = "{app_label} - {detection_name} - Rule"
CONTENTCTL_BASELINE_STANZA_NAME_FORMAT_TEMPLATE = "{app_label} - {detection_name}"
CONTENTCTL_RESPONSE_TASK_NAME_FORMAT_TEMPLATE = "{app_label} - {detection_name} - Response Task"

ES_SEARCH_STANZA_NAME_FORMAT_AFTER_CLONING_IN_PRODUCT_TEMPLATE = "{security_domain_value} - {search_name} - Rule"
SECURITY_DOMAIN_MAX_LENGTH = max([len(SecurityDomain[value]) for value in SecurityDomain._member_map_])
CONTENTCTL_MAX_STANZA_LENGTH = ES_MAX_STANZA_LENGTH - len(ES_SEARCH_STANZA_NAME_FORMAT_AFTER_CLONING_IN_PRODUCT_TEMPLATE.format(security_domain_value="X"*SECURITY_DOMAIN_MAX_LENGTH,search_name=""))
CONTENTCTL_MAX_SEARCH_NAME_LENGTH = CONTENTCTL_MAX_STANZA_LENGTH - len(CONTENTCTL_DETECTION_STANZA_NAME_FORMAT_TEMPLATE.format(app_label="ESCU", detection_name=""))