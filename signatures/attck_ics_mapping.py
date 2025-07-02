# ATT&CK for ICS Technique ID to Name Mapping
# This file maps technique IDs to their names and MicroAttackStage values

from signatures.attack_stages import MicroAttackStage

# Technique ID to MicroAttackStage mapping
technique_to_stage = {
    # Initial Access
    "T0817": MicroAttackStage.DRIVE_BY_COMPROMISE,
    "T0819": MicroAttackStage.EXPLOIT_PUBLIC_FACING_APP_ICS,
    "T0866": MicroAttackStage.EXPLOITATION_OF_REMOTE_SERVICES_ICS,
    "T0822": MicroAttackStage.EXTERNAL_REMOTE_SERVICES,
    "T0883": MicroAttackStage.INTERNET_ACCESSIBLE_DEVICE,
    "T0886": MicroAttackStage.REMOTE_SERVICES_ICS,
    "T0847": MicroAttackStage.REPLICATION_THROUGH_REMOVABLE_MEDIA,
    "T0848": MicroAttackStage.ROGUE_MASTER,
    "T0865": MicroAttackStage.SPEARPHISHING_ATTACHMENT_ICS,
    "T0862": MicroAttackStage.SUPPLY_CHAIN_COMPROMISE,
    "T0864": MicroAttackStage.TRANSIENT_CYBER_ASSET,
    "T0860": MicroAttackStage.WIRELESS_COMPROMISE,
    
    # Execution
    "T0895": MicroAttackStage.AUTORUN_IMAGE,
    "T0858": MicroAttackStage.CHANGE_OPERATING_MODE,
    "T0807": MicroAttackStage.COMMAND_LINE_INTERFACE_ICS,
    "T0871": MicroAttackStage.EXECUTION_THROUGH_API,
    "T0823": MicroAttackStage.GRAPHICAL_USER_INTERFACE,
    "T0874": MicroAttackStage.HOOKING_ICS,
    "T0821": MicroAttackStage.MODIFY_CONTROLLER_TASKING,
    "T0834": MicroAttackStage.NATIVE_API_ICS,
    "T0853": MicroAttackStage.SCRIPTING_ICS,
    "T0863": MicroAttackStage.USER_EXECUTION_ICS,
    
    # Persistence
    "T0891": MicroAttackStage.HARDCODED_CREDENTIALS,
    "T0889": MicroAttackStage.MODIFY_PROGRAM,
    "T0839": MicroAttackStage.MODULE_FIRMWARE,
    "T0873": MicroAttackStage.PROJECT_FILE_INFECTION,
    "T0857": MicroAttackStage.SYSTEM_FIRMWARE,
    "T0859": MicroAttackStage.VALID_ACCOUNTS_ICS,
    
    # Privilege Escalation
    "T0890": MicroAttackStage.EXPLOITATION_FOR_PRIVILEGE_ESCALATION,
    # T0874 (Hooking) already mapped above
    
    # Evasion
    # T0858 (Change Operating Mode) already mapped above
    "T0820": MicroAttackStage.EXPLOITATION_FOR_EVASION,
    "T0872": MicroAttackStage.INDICATOR_REMOVAL_ON_HOST_ICS,
    "T0849": MicroAttackStage.MASQUERADING_ICS,
    "T0851": MicroAttackStage.ROOTKIT_ICS,
    "T0856": MicroAttackStage.SPOOF_REPORTING_MESSAGE,
    "T0894": MicroAttackStage.SYSTEM_BINARY_PROXY_EXECUTION,
    
    # Discovery
    "T0840": MicroAttackStage.NETWORK_CONNECTION_ENUMERATION,
    "T0842": MicroAttackStage.NETWORK_SNIFFING_ICS,
    "T0846": MicroAttackStage.REMOTE_SYSTEM_DISCOVERY_ICS,
    "T0888": MicroAttackStage.REMOTE_SYSTEM_INFORMATION_DISCOVERY,
    "T0887": MicroAttackStage.WIRELESS_SNIFFING,
    
    # Lateral Movement
    "T0812": MicroAttackStage.DEFAULT_CREDENTIALS,
    # T0866, T0891, T0859 already mapped above
    "T0867": MicroAttackStage.LATERAL_TOOL_TRANSFER,
    "T0843": MicroAttackStage.PROGRAM_DOWNLOAD,
    # T0886 already mapped above
    
    # Collection
    "T0830": MicroAttackStage.ADVERSARY_IN_THE_MIDDLE_ICS,
    "T0802": MicroAttackStage.AUTOMATED_COLLECTION_ICS,
    "T0811": MicroAttackStage.DATA_FROM_INFORMATION_REPOSITORIES_ICS,
    "T0893": MicroAttackStage.DATA_FROM_LOCAL_SYSTEM_ICS,
    "T0868": MicroAttackStage.DETECT_OPERATING_MODE,
    "T0877": MicroAttackStage.IO_IMAGE,
    "T0801": MicroAttackStage.MONITOR_PROCESS_STATE,
    "T0861": MicroAttackStage.POINT_AND_TAG_IDENTIFICATION,
    "T0845": MicroAttackStage.PROGRAM_UPLOAD,
    "T0852": MicroAttackStage.SCREEN_CAPTURE_ICS,
    # T0887 already mapped above
    
    # Command and Control
    "T0885": MicroAttackStage.COMMONLY_USED_PORT,
    "T0884": MicroAttackStage.CONNECTION_PROXY,
    "T0869": MicroAttackStage.STANDARD_APPLICATION_LAYER_PROTOCOL,
    
    # Inhibit Response Function
    "T0800": MicroAttackStage.ACTIVATE_FIRMWARE_UPDATE_MODE,
    "T0878": MicroAttackStage.ALARM_SUPPRESSION,
    "T0803": MicroAttackStage.BLOCK_COMMAND_MESSAGE,
    "T0804": MicroAttackStage.BLOCK_REPORTING_MESSAGE,
    "T0805": MicroAttackStage.BLOCK_SERIAL_COM,
    "T0892": MicroAttackStage.CHANGE_CREDENTIAL,
    "T0809": MicroAttackStage.DATA_DESTRUCTION_ICS,
    "T0814": MicroAttackStage.DENIAL_OF_SERVICE_ICS,
    "T0816": MicroAttackStage.DEVICE_RESTART_SHUTDOWN,
    "T0835": MicroAttackStage.MANIPULATE_IO_IMAGE,
    "T0838": MicroAttackStage.MODIFY_ALARM_SETTINGS,
    # T0851 (Rootkit) already mapped above
    "T0881": MicroAttackStage.SERVICE_STOP_ICS,
    # T0857 (System Firmware) already mapped above
    
    # Impair Process Control
    "T0806": MicroAttackStage.BRUTE_FORCE_IO,
    "T0836": MicroAttackStage.MODIFY_PARAMETERS,
    # T0839 (Module Firmware) already mapped above
    # T0856 (Spoof Reporting Message) already mapped above
    "T0855": MicroAttackStage.UNAUTHORIZED_COMMAND_MESSAGE,
    
    # Impact
    "T0879": MicroAttackStage.DAMAGE_TO_PROPERTY,
    "T0813": MicroAttackStage.DENIAL_OF_CONTROL,
    "T0815": MicroAttackStage.DENIAL_OF_VIEW,
    "T0826": MicroAttackStage.LOSS_OF_AVAILABILITY,
    "T0827": MicroAttackStage.LOSS_OF_CONTROL,
    "T0828": MicroAttackStage.LOSS_OF_PRODUCTIVITY_AND_REVENUE,
    "T0837": MicroAttackStage.LOSS_OF_PROTECTION,
    "T0880": MicroAttackStage.LOSS_OF_SAFETY,
    "T0829": MicroAttackStage.LOSS_OF_VIEW,
    "T0831": MicroAttackStage.MANIPULATION_OF_CONTROL,
    "T0832": MicroAttackStage.MANIPULATION_OF_VIEW,
    "T0882": MicroAttackStage.THEFT_OF_OPERATIONAL_INFORMATION,
}

# Reverse mapping: MicroAttackStage to Technique ID
stage_to_technique = {v: k for k, v in technique_to_stage.items()}

# Technique names with IDs for display
technique_names = {
    # Initial Access
    "T0817": "Drive-by Compromise",
    "T0819": "Exploit Public-Facing Application",
    "T0866": "Exploitation of Remote Services",
    "T0822": "External Remote Services",
    "T0883": "Internet Accessible Device",
    "T0886": "Remote Services",
    "T0847": "Replication Through Removable Media",
    "T0848": "Rogue Master",
    "T0865": "Spearphishing Attachment",
    "T0862": "Supply Chain Compromise",
    "T0864": "Transient Cyber Asset",
    "T0860": "Wireless Compromise",
    
    # Execution
    "T0895": "Autorun Image",
    "T0858": "Change Operating Mode",
    "T0807": "Command-Line Interface",
    "T0871": "Execution through API",
    "T0823": "Graphical User Interface",
    "T0874": "Hooking",
    "T0821": "Modify Controller Tasking",
    "T0834": "Native API",
    "T0853": "Scripting",
    "T0863": "User Execution",
    
    # Persistence
    "T0891": "Hardcoded Credentials",
    "T0889": "Modify Program",
    "T0839": "Module Firmware",
    "T0873": "Project File Infection",
    "T0857": "System Firmware",
    "T0859": "Valid Accounts",
    
    # Privilege Escalation
    "T0890": "Exploitation for Privilege Escalation",
    
    # Evasion
    "T0820": "Exploitation for Evasion",
    "T0872": "Indicator Removal on Host",
    "T0849": "Masquerading",
    "T0851": "Rootkit",
    "T0856": "Spoof Reporting Message",
    "T0894": "System Binary Proxy Execution",
    
    # Discovery
    "T0840": "Network Connection Enumeration",
    "T0842": "Network Sniffing",
    "T0846": "Remote System Discovery",
    "T0888": "Remote System Information Discovery",
    "T0887": "Wireless Sniffing",
    
    # Lateral Movement
    "T0812": "Default Credentials",
    "T0867": "Lateral Tool Transfer",
    "T0843": "Program Download",
    
    # Collection
    "T0830": "Adversary-in-the-Middle",
    "T0802": "Automated Collection",
    "T0811": "Data from Information Repositories",
    "T0893": "Data from Local System",
    "T0868": "Detect Operating Mode",
    "T0877": "I/O Image",
    "T0801": "Monitor Process State",
    "T0861": "Point & Tag Identification",
    "T0845": "Program Upload",
    "T0852": "Screen Capture",
    
    # Command and Control
    "T0885": "Commonly Used Port",
    "T0884": "Connection Proxy",
    "T0869": "Standard Application Layer Protocol",
    
    # Inhibit Response Function
    "T0800": "Activate Firmware Update Mode",
    "T0878": "Alarm Suppression",
    "T0803": "Block Command Message",
    "T0804": "Block Reporting Message",
    "T0805": "Block Serial COM",
    "T0892": "Change Credential",
    "T0809": "Data Destruction",
    "T0814": "Denial of Service",
    "T0816": "Device Restart/Shutdown",
    "T0835": "Manipulate I/O Image",
    "T0838": "Modify Alarm Settings",
    "T0881": "Service Stop",
    
    # Impair Process Control
    "T0806": "Brute Force I/O",
    "T0836": "Modify Parameter",
    "T0855": "Unauthorized Command Message",
    
    # Impact
    "T0879": "Damage to Property",
    "T0813": "Denial of Control",
    "T0815": "Denial of View",
    "T0826": "Loss of Availability",
    "T0827": "Loss of Control",
    "T0828": "Loss of Productivity and Revenue",
    "T0837": "Loss of Protection",
    "T0880": "Loss of Safety",
    "T0829": "Loss of View",
    "T0831": "Manipulation of Control",
    "T0832": "Manipulation of View",
    "T0882": "Theft of Operational Information",
}

# Get technique display name with ID
def get_technique_display(stage):
    """Get the display name for a technique given its MicroAttackStage."""
    if stage in stage_to_technique:
        tech_id = stage_to_technique[stage]
        tech_name = technique_names.get(tech_id, "Unknown Technique")
        return f"{tech_name} ({tech_id})"
    return None