"""OCSF enumeration types aligned with schema v1.3 class and activity identifiers."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class OCSFClass(IntEnum):
    """OCSF event class UIDs used by soc-chronicle."""

    FILE_ACTIVITY = 1001
    KERNEL_EXTENSION_ACTIVITY = 1002
    KERNEL_ACTIVITY = 1003
    MEMORY_ACTIVITY = 1004
    MODULE_ACTIVITY = 1005
    SCHEDULED_JOB_ACTIVITY = 1006
    PROCESS_ACTIVITY = 1007
    SMB_ACTIVITY = 1008
    REGISTRY_KEY_ACTIVITY = 201001
    REGISTRY_VALUE_ACTIVITY = 201002
    AUTHENTICATION = 3002
    ACCOUNT_CHANGE = 3001
    AUTHORIZE_SESSION = 3003
    ENTITY_MANAGEMENT = 3004
    USER_ACCESS = 3005
    GROUP_MANAGEMENT = 3006
    NETWORK_ACTIVITY = 4001
    HTTP_ACTIVITY = 4002
    DNS_ACTIVITY = 4003
    DHCP_ACTIVITY = 4004
    RDP_ACTIVITY = 4006
    SSH_ACTIVITY = 4007
    DETECTION_FINDING = 2004
    INCIDENT_FINDING = 2005
    VULNERABILITY_FINDING = 2002


class CategoryUid(IntEnum):
    """OCSF category UIDs."""

    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IDENTITY_ACCESS = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5


class ActivityId(IntEnum):
    """Common OCSF activity identifiers across event classes."""

    UNKNOWN = 0
    CREATE = 1
    READ = 2
    UPDATE = 3
    DELETE = 4
    START = 5
    STOP = 6
    OPEN = 7
    CLOSE = 8
    CONNECT = 9
    DISCONNECT = 10
    LOGIN = 11
    LOGOUT = 12
    AUTHENTICATE = 13
    LAUNCH = 14
    TERMINATE = 15
    SET = 16
    QUERY = 17
    TRAFFIC = 18
    REQUEST = 19
    RESPONSE = 20
    DETECT = 21
    ALERT = 22


class SeverityId(IntEnum):
    """OCSF severity scale (0=Unknown, 6=Fatal)."""

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class StatusId(IntEnum):
    """OCSF event status identifiers."""

    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class SourceType(StrEnum):
    """Known log source identifiers for normalized events."""

    UNKNOWN = "unknown"
    SYSMON = "sysmon"
    WINDOWS_SECURITY = "windows_security"
    LINUX_AUDITD = "linux_auditd"
    LINUX_SYSMON = "linux_sysmon"
    MACOS_UNIFIED = "macos_unified"
    ANDROID = "android"
    ZEEK = "zeek"
    SURICATA = "suricata"
    SNORT = "snort"
    APACHE = "apache"
    NGINX = "nginx"
    FIREWALL = "firewall"
    CLOUDTRAIL = "cloudtrail"
    AZURE_ACTIVITY = "azure_activity"
    OKTA = "okta"
    ENTRA_ID = "entra_id"
    WAZUH = "wazuh"
    SPLUNK = "splunk"
    CROWDSTRIKE = "crowdstrike"
    ELASTIC_ECS = "elastic_ecs"
    GENERIC = "generic"


def compute_type_uid(class_uid: OCSFClass | int, activity_id: ActivityId | int) -> int:
    """Compute OCSF type_uid as ``class_uid * 100 + activity_id``.

    OCSF encodes the activity within the class namespace using this formula.
    """
    return int(class_uid) * 100 + int(activity_id)


def activity_name_for(activity_id: ActivityId) -> str:
    """Return a human-readable activity name for a given activity_id."""
    return activity_id.name.replace("_", " ").title()


# Mapping from class_uid to category_uid for validation and type construction.
CLASS_TO_CATEGORY: dict[int, CategoryUid] = {
    OCSFClass.FILE_ACTIVITY: CategoryUid.SYSTEM_ACTIVITY,
    OCSFClass.SCHEDULED_JOB_ACTIVITY: CategoryUid.SYSTEM_ACTIVITY,
    OCSFClass.PROCESS_ACTIVITY: CategoryUid.SYSTEM_ACTIVITY,
    OCSFClass.REGISTRY_KEY_ACTIVITY: CategoryUid.SYSTEM_ACTIVITY,
    OCSFClass.REGISTRY_VALUE_ACTIVITY: CategoryUid.SYSTEM_ACTIVITY,
    OCSFClass.AUTHENTICATION: CategoryUid.IDENTITY_ACCESS,
    OCSFClass.ACCOUNT_CHANGE: CategoryUid.IDENTITY_ACCESS,
    OCSFClass.NETWORK_ACTIVITY: CategoryUid.NETWORK_ACTIVITY,
    OCSFClass.HTTP_ACTIVITY: CategoryUid.NETWORK_ACTIVITY,
    OCSFClass.DNS_ACTIVITY: CategoryUid.NETWORK_ACTIVITY,
    OCSFClass.DETECTION_FINDING: CategoryUid.FINDINGS,
    OCSFClass.INCIDENT_FINDING: CategoryUid.FINDINGS,
    OCSFClass.VULNERABILITY_FINDING: CategoryUid.FINDINGS,
    OCSFClass.KERNEL_ACTIVITY: CategoryUid.SYSTEM_ACTIVITY,
    OCSFClass.MODULE_ACTIVITY: CategoryUid.SYSTEM_ACTIVITY,
    OCSFClass.MEMORY_ACTIVITY: CategoryUid.SYSTEM_ACTIVITY,
    OCSFClass.SMB_ACTIVITY: CategoryUid.NETWORK_ACTIVITY,
    OCSFClass.DHCP_ACTIVITY: CategoryUid.NETWORK_ACTIVITY,
    OCSFClass.RDP_ACTIVITY: CategoryUid.NETWORK_ACTIVITY,
    OCSFClass.SSH_ACTIVITY: CategoryUid.NETWORK_ACTIVITY,
    OCSFClass.AUTHORIZE_SESSION: CategoryUid.IDENTITY_ACCESS,
    OCSFClass.USER_ACCESS: CategoryUid.IDENTITY_ACCESS,
}
