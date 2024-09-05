from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict, HttpUrl, field_validator, computed_field, field_serializer
from typing import Any
from enum import StrEnum
import datetime
from contentctl.objects.annotated_types import MITRE_ATTACK_ID_TYPE

class MitreTactics(StrEnum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command And Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class AttackGroupMatrix(StrEnum):
    enterprise_attack = "enterprise-attack"
    ics_attack = "ics-attack"
    mobile_attack = "mobile-attack"


class AttackGroupType(StrEnum):
    intrusion_set = "intrusion-set"
    attack_pattern = "attack-pattern"
    relationship = "relationship"

class MitreExternalReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source_name: str
    external_id: None | str = None 
    url: None | HttpUrl = None
    description: None | str = None

    @field_serializer("url")
    def serialize_url(self, url: None | HttpUrl):
        if url is None:
            return None
        return str(url)


class MitreAbstract(BaseModel):
    id: str
    created: datetime.datetime
    contributors: list[str] = []
    
    external_references: list[MitreExternalReference]
    matrix: list[AttackGroupMatrix]
    mitre_attack_spec_version: None | str
    mitre_deprecated: bool
    modified: datetime.datetime
    modified_by_ref: str
    object_marking_refs: list[str]
    type: AttackGroupType
    url: None | HttpUrl

    @field_serializer("url")
    def serialize_url(self, url: None | HttpUrl):
        if url is None:
            return None
        return str(url)

    @field_serializer("created","modified")
    def serialize_fields_base(self, val:Any):
        '''
        datetime object cannot be serialized, so we need to define this
        function otherwise serialization throws errors the error:
        Object of type datetime is not JSON serializable
        '''
        return str(val)

    @field_validator("mitre_deprecated", mode="before")
    def standardize_mitre_deprecated(cls, mitre_deprecated:bool | None) -> bool:
        '''
        For some reason, the API will return either a bool for mitre_deprecated OR
        None. We simplify our typing by converting None to False, and assuming that
        if deprecated is None, then the group is not deprecated.
        '''
        if mitre_deprecated is None:
            return False
        return mitre_deprecated

    @field_validator("contributors", "external_references", "matrix", mode="before")
    def standardize_contributors(cls, contributors:list[str] | None) -> list[str]:
        '''
        For some reason, the API will return either a list of strings for contributors OR
        None. We simplify our typing by converting None to an empty list.
        '''
        if contributors is None:
            return []
        return contributors

class MitreTechniqueGroup(MitreAbstract):
    created_by_ref: str
    mitre_version: str

class MitrePlatform(StrEnum):
    linux = "Linux"
    macos = "macOS"
    windows = "Windows"
    office_365 = "Office 365"
    iaas = "IaaS"
    azure_ad = "Azure AD"
    saas = "SaaS"
    google_workspace = "Google Workspace"
    network = "Network"
    containers = "Containers"
    pre = "PRE"




class MitreDataSource(StrEnum):
    active_directory__active_directory_credential_request = "Active Directory: Active Directory Credential Request"
    active_directory__active_directory_object_access = "Active Directory: Active Directory Object Access"
    active_directory__active_directory_object_creation = "Active Directory: Active Directory Object Creation"
    active_directory__active_directory_object_deletion = "Active Directory: Active Directory Object Deletion"
    active_directory__active_directory_object_modification = "Active Directory: Active Directory Object Modification"
    application_log__application_log_content = "Application Log: Application Log Content"
    certificate__certificate_registration = "Certificate: Certificate Registration"
    cloud_service__cloud_service_disable = "Cloud Service: Cloud Service Disable"
    cloud_service__cloud_service_enumeration = "Cloud Service: Cloud Service Enumeration"
    cloud_service__cloud_service_metadata = "Cloud Service: Cloud Service Metadata"
    cloud_service__cloud_service_modification = "Cloud Service: Cloud Service Modification"
    cloud_storage__cloud_storage_access = "Cloud Storage: Cloud Storage Access"
    cloud_storage__cloud_storage_creation = "Cloud Storage: Cloud Storage Creation"
    cloud_storage__cloud_storage_deletion = "Cloud Storage: Cloud Storage Deletion"
    cloud_storage__cloud_storage_enumeration = "Cloud Storage: Cloud Storage Enumeration"
    cloud_storage__cloud_storage_metadata = "Cloud Storage: Cloud Storage Metadata"
    cloud_storage__cloud_storage_modification = "Cloud Storage: Cloud Storage Modification"
    command__command_execution = "Command: Command Execution"
    container__container_creation = "Container: Container Creation"
    container__container_enumeration = "Container: Container Enumeration"
    container__container_start = "Container: Container Start"
    domain_name__active_dns = "Domain Name: Active DNS"
    domain_name__domain_registration = "Domain Name: Domain Registration"
    domain_name__passive_dns = "Domain Name: Passive DNS"
    drive__drive_access = "Drive: Drive Access"
    drive__drive_creation = "Drive: Drive Creation"
    drive__drive_modification = "Drive: Drive Modification"
    driver__driver_load = "Driver: Driver Load"
    driver__driver_metadata = "Driver: Driver Metadata"
    file__file_access = "File: File Access"
    file__file_creation = "File: File Creation"
    file__file_deletion = "File: File Deletion"
    file__file_metadata = "File: File Metadata"
    file__file_modification = "File: File Modification"
    firewall__firewall_disable = "Firewall: Firewall Disable"
    firewall__firewall_enumeration = "Firewall: Firewall Enumeration"
    firewall__firewall_metadata = "Firewall: Firewall Metadata"
    firewall__firewall_rule_modification = "Firewall: Firewall Rule Modification"
    firmware__firmware_modification = "Firmware: Firmware Modification"
    group__group_enumeration = "Group: Group Enumeration"
    group__group_metadata = "Group: Group Metadata"
    group__group_modification = "Group: Group Modification"
    image__image_creation = "Image: Image Creation"
    image__image_deletion = "Image: Image Deletion"
    image__image_metadata = "Image: Image Metadata"
    image__image_modification = "Image: Image Modification"
    instance__instance_creation = "Instance: Instance Creation"
    instance__instance_deletion = "Instance: Instance Deletion"
    instance__instance_enumeration = "Instance: Instance Enumeration"
    instance__instance_metadata = "Instance: Instance Metadata"
    instance__instance_modification = "Instance: Instance Modification"
    instance__instance_start = "Instance: Instance Start"
    instance__instance_stop = "Instance: Instance Stop"
    internet_scan__response_content = "Internet Scan: Response Content"
    internet_scan__response_metadata = "Internet Scan: Response Metadata"
    kernel__kernel_module_load = "Kernel: Kernel Module Load"
    logon_session__logon_session_creation = "Logon Session: Logon Session Creation"
    logon_session__logon_session_metadata = "Logon Session: Logon Session Metadata"
    malware_repository__malware_content = "Malware Repository: Malware Content"
    malware_repository__malware_metadata = "Malware Repository: Malware Metadata"
    module__module_load = "Module: Module Load"
    named_pipe__named_pipe_metadata = "Named Pipe: Named Pipe Metadata"
    network_share__network_share_access = "Network Share: Network Share Access"
    network_traffic__network_connection_creation = "Network Traffic: Network Connection Creation"
    network_traffic__network_traffic_content = "Network Traffic: Network Traffic Content"
    network_traffic__network_traffic_flow = "Network Traffic: Network Traffic Flow"
    persona__social_media = "Persona: Social Media"
    pod__pod_creation = "Pod: Pod Creation"
    pod__pod_enumeration = "Pod: Pod Enumeration"
    pod__pod_modification = "Pod: Pod Modification"
    process__os_api_execution = "Process: OS API Execution"
    process__process_access = "Process: Process Access"
    process__process_creation = "Process: Process Creation"
    process__process_metadata = "Process: Process Metadata"
    process__process_modification = "Process: Process Modification"
    process__process_termination = "Process: Process Termination"
    scheduled_job__scheduled_job_creation = "Scheduled Job: Scheduled Job Creation"
    scheduled_job__scheduled_job_metadata = "Scheduled Job: Scheduled Job Metadata"
    scheduled_job__scheduled_job_modification = "Scheduled Job: Scheduled Job Modification"
    script__script_execution = "Script: Script Execution"
    sensor_health__host_status = "Sensor Health: Host Status"
    service__service_creation = "Service: Service Creation"
    service__service_metadata = "Service: Service Metadata"
    service__service_modification = "Service: Service Modification"
    snapshot__snapshot_creation = "Snapshot: Snapshot Creation"
    snapshot__snapshot_deletion = "Snapshot: Snapshot Deletion"
    snapshot__snapshot_enumeration = "Snapshot: Snapshot Enumeration"
    snapshot__snapshot_metadata = "Snapshot: Snapshot Metadata"
    snapshot__snapshot_modification = "Snapshot: Snapshot Modification"
    user_account__user_account_authentication = "User Account: User Account Authentication"
    user_account__user_account_creation = "User Account: User Account Creation"
    user_account__user_account_deletion = "User Account: User Account Deletion"
    user_account__user_account_metadata = "User Account: User Account Metadata"
    user_account__user_account_modification = "User Account: User Account Modification"
    volume__volume_creation = "Volume: Volume Creation"
    volume__volume_deletion = "Volume: Volume Deletion"
    volume__volume_enumeration = "Volume: Volume Enumeration"
    volume__volume_metadata = "Volume: Volume Metadata"
    volume__volume_modification = "Volume: Volume Modification"
    wmi__wmi_creation = "WMI: WMI Creation"
    web_credential__web_credential_creation = "Web Credential: Web Credential Creation"
    web_credential__web_credential_usage = "Web Credential: Web Credential Usage"
    windows_registry__windows_registry_key_access = "Windows Registry: Windows Registry Key Access"
    windows_registry__windows_registry_key_creation = "Windows Registry: Windows Registry Key Creation"
    windows_registry__windows_registry_key_deletion = "Windows Registry: Windows Registry Key Deletion"
    windows_registry__windows_registry_key_modification = "Windows Registry: Windows Registry Key Modification"

class MitreDefenseBypassed(StrEnum):
    anti_virus = "Anti Virus"
    anti_virus2 = "Anti-virus"
    application_control = "Application Control"
    application_control2 = "Application control"
    autoruns_analysis = "Autoruns Analysis"
    binary_analysis = "Binary Analysis"
    defensive_network_service_scanning = "Defensive network service scanning"
    digital_certificate_validation = "Digital Certificate Validation"
    encryption = "Encryption"
    file_monitoring = "File Monitoring"
    file_monitoring2 = "File monitoring"
    file_system_access_controls = "File system access controls"
    firewall = "Firewall"
    gatekeeper = "Gatekeeper"
    heuristic_detection = "Heuristic Detection"
    heuristic_detection2 = "Heuristic detection"
    host_forensic_analysis = "Host Forensic Analysis"
    host_intrusion_prevention_systems = "Host Intrusion Prevention Systems"
    host_forensic_analysis2 = "Host forensic analysis"
    host_intrusion_prevention_systems2 = "Host intrusion prevention systems"
    log_analysis = "Log Analysis"
    log_analysis2 = "Log analysis"
    multi_factor_authentication = "Multi-Factor Authentication"
    network_intrusion_detection_system = "Network Intrusion Detection System"
    notarization = "Notarization"
    signature_based_detection = "Signature-based Detection"
    signature_based_detection2 = "Signature-based detection"
    static_file_analysis = "Static File Analysis"
    system_access_controls = "System Access Controls"
    system_access_controls2 = "System access controls"
    user_mode_signature_validation = "User Mode Signature Validation"
    web_content_filters = "Web Content Filters"
    windows_user_account_control = "Windows User Account Control"


class MitreSystemRequirements(StrEnum):
    _net_framework_version_4_or_higher = ".NET Framework version 4 or higher"
    ability_to_query_some_registry_locations_depends_on_the_adversary_s_level_of_access__user_permissions_are_usually_limited_to_access_of_user_related_registry_keys_ = "Ability to query some Registry locations depends on the adversary's level of access. User permissions are usually limited to access of user-related Registry keys."
    ability_to_update_component_device_firmware_from_the_host_operating_system_ = "Ability to update component device firmware from the host operating system."
    access_to_domain_controller_or_backup = "Access to Domain Controller or backup"
    access_to_files = "Access to files"
    access_to_shared_folders_and_content_with_write_permissions = "Access to shared folders and content with write permissions"
    active_remote_service_accepting_connections_and_valid_credentials = "Active remote service accepting connections and valid credentials"
    an_ssh_server_is_configured_and_running_ = "An SSH server is configured and running."
    an_externally_facing_login_portal_is_configured_ = "An externally facing login portal is configured."
    compiler_software__either_native_to_the_system_or_delivered_by_the_adversary_ = "Compiler software (either native to the system or delivered by the adversary)"
    established_network_share_connection_to_a_remote_system__level_of_access_depends_on_permissions_of_the_account_used_ = "Established network share connection to a remote system. Level of access depends on permissions of the account used."
    kerberos_authentication_enabled = "Kerberos authentication enabled"
    ms_office_version_specified_in__code__vba_project__code__stream_must_match_host = "MS Office version specified in <code>_VBA_PROJECT</code> stream must match host"
    microsoft_core_xml_services__msxml__or_access_to_wmic_exe = "Microsoft Core XML Services (MSXML) or access to wmic.exe"
    ntfs_partitioned_hard_drive = "NTFS partitioned hard drive"
    network_interface_access_and_packet_capture_driver = "Network interface access and packet capture driver"
    permissions_to_access_directories__files__and_api_endpoints_that_store_information_of_interest_ = "Permissions to access directories, files, and API endpoints that store information of interest."
    presence_of_physical_medium_or_device = "Presence of physical medium or device"
    privileges_to_access_certain_files_and_directories = "Privileges to access certain files and directories"
    privileges_to_access_network_shared_drive = "Privileges to access network shared drive"
    privileges_to_access_removable_media_drive_and_files = "Privileges to access removable media drive and files"
    python_is_installed_ = "Python is installed."
    rdp_service_enabled__account_in_the_remote_desktop_users_group = "RDP service enabled, account in the Remote Desktop Users group"
    remote_exploitation_for_execution_requires_a_remotely_accessible_service_reachable_over_the_network_or_other_vector_of_access_such_as_spearphishing_or_drive_by_compromise_ = "Remote exploitation for execution requires a remotely accessible service reachable over the network or other vector of access such as spearphishing or drive-by compromise."
    removable_media_allowed__autorun_enabled_or_vulnerability_present_that_allows_for_code_execution = "Removable media allowed, Autorun enabled or vulnerability present that allows for code execution"
    smb_enabled__host_network_firewalls_not_blocking_smb_ports_between_source_and_destination__use_of_domain_account_in_administrator_group_on_remote_system_or_default_system_admin_account_ = "SMB enabled; Host/network firewalls not blocking SMB ports between source and destination; Use of domain account in administrator group on remote system or default system admin account."
    ssh_service_enabled__trust_relationships_configured__established_connections = "SSH service enabled, trust relationships configured, established connections"
    secure_boot_disabled_on_systems_running_windows_8_and_later = "Secure boot disabled on systems running Windows 8 and later"
    unpatched_software_or_otherwise_vulnerable_target__depending_on_the_target_and_goal__the_system_and_exploitable_service_may_need_to_be_remotely_accessible_from_the_internal_network_ = "Unpatched software or otherwise vulnerable target. Depending on the target and goal, the system and exploitable service may need to be remotely accessible from the internal network."
    user = "User"
    vnc_server_installed_and_listening_for_connections_ = "VNC server installed and listening for connections."
    valid_domain_account = "Valid domain account"
    valid_domain_account_or_the_ability_to_sniff_traffic_within_a_domain = "Valid domain account or the ability to sniff traffic within a domain"



class MitreEffectivePermission(StrEnum):
    administrator = "Administrator"
    system = "SYSTEM"
    user = "User"
    root = "root"
class MitreImpactType(StrEnum):
    availability = "Availability"
    integrity = "Integrity"
class MitrePermissionRequired(StrEnum):
    administrator = "Administrator"
    system = "SYSTEM"
    user = "User"
    root = "root"

class MitreTactic(StrEnum):
    collection = "collection"
    command_and_control = "command-and-control"
    credential_access = "credential-access"
    defense_evasion = "defense-evasion"
    discovery = "discovery"
    execution = "execution"
    exfiltration = "exfiltration"
    impact = "impact"
    initial_access = "initial-access"
    lateral_movement = "lateral-movement"
    persistence = "persistence"
    privilege_escalation = "privilege-escalation"
    reconnaissance = "reconnaissance"
    resource_development = "resource-development"

class MitreEnterpriseTechnique(MitreTechniqueGroup):
    model_config = ConfigDict(extra='forbid')
    data_sources: list[MitreDataSource]
    defense_bypassed: list[MitreDefenseBypassed]
    effective_permissions: list[MitreEffectivePermission]
    impact_type: list[MitreImpactType]
    is_subtechnique: bool
    network_requirements: bool = False
    permissions_required: list[MitrePermissionRequired]
    platform: list[MitrePlatform]
    remote_support: bool
    system_requirements: list[MitreSystemRequirements]
    tactic: list[MitreTactic]
    tactic_type: None
    technique: str
    technique_description: str
    technique_detection: str
    technique_id: MITRE_ATTACK_ID_TYPE

    groups: list[MitreAttackGroup] = []


    
    def __hash__(self) -> int:
        return id(self)
    
    def updateGroups(self, relationships:list[MitreEnterpriseRelationship], groups:list[MitreAttackGroup]) -> None:
        # We only care about intrusion-set
        intrusion_relationships = list(filter(lambda r: r.target_object == self.id, relationships))
        self.groups = [group for group in groups if group.id in [ir.source_object for ir in intrusion_relationships]]
        return None
    
    
    
    @property
    def mitre_attack_technique(self) -> str:
        return self.technique_id

    
    @property
    def mitre_attack_groups(self) -> list[str]:
        return [group.group for group in self.groups]

    
    @property
    def mitre_attack_id(self) -> MITRE_ATTACK_ID_TYPE:
        return self.technique_id

    
    @property
    def mitre_attack_tactics(self) -> list[str]:
        return [tactic.value.replace('-',' ').title() for tactic in self.tactic] 

    @field_validator("network_requirements", 
                     "remote_support", 
                     mode="before")
    def standardize_bool_field(cls, bool_field:bool | None) -> bool:
        '''
        For some reason, the API will return either a bool for remote_support OR
        None. We simplify our typing by converting None to False, and assuming that
        if deprecated is None, then the group is not deprecated.
        '''
        if bool_field is None:
            return False
        return bool_field
    
    @field_validator("data_sources",
                     "defense_bypassed", 
                     "effective_permissions", 
                     "impact_type",
                     "permissions_required", 
                     "system_requirements", 
                     mode="before")
    def standardize_list_fields_child(cls, list_field:list[str] | None) -> list[str]:
        '''
        For some reason, the API will return either a list of strings for contributors OR
        None. We simplify our typing by converting None to an empty list.
        '''
        if list_field is None:
            return []
        return list_field
    

class MitreEnterpriseRelationship(MitreAbstract):
    model_config = ConfigDict(extra='forbid')
    created_by_ref: None | str
    mitre_version: None | str
    relationship: str
    relationship_description: None | str
    source_object: str
    target_object: str
    
           

class MitreAttackGroup(MitreTechniqueGroup):
    model_config = ConfigDict(extra='forbid')
    group: str
    group_aliases: list[str]
    group_description: str
    group_id: str
    
    
    
    

    



# TODO (#266): disable the use_enum_values configuration
class MitreAttackEnrichment(BaseModel):
    ConfigDict(use_enum_values=True)
    mitre_attack_technique: MitreEnterpriseTechnique = Field(...)
    #Exclude this field from serialization - it is very large and not useful in JSON objects
    mitre_attack_group_objects: list[MitreAttackGroup] = Field(..., exclude=True)
    def _hash_(self) -> int:
        return id(self)
    
    @computed_field
    def mitre_attack_groups(self) -> list[str]:
        return [group.group for group in self.mitre_attack_group_objects]

    @computed_field
    def mitre_attack_id(self) -> MITRE_ATTACK_ID_TYPE:
        return self.mitre_attack_technique.id

    @computed_field
    def mitre_attack_tactics(self) -> list[str]:
        return [tactic.value.replace('-',' ').title() for tactic in self.mitre_attack_technique.tactic] 

# The following Enums are complete, but likely to change. Do we want to include them as enums,
# or just have this as a string field?

