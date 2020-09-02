sec = {  # Security
    1102: {"Descr": "The audit log was cleared",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId"},

    4616: {"Descr": "The system time was changed",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "PreviousTime": "PreviousTime",
           "NewTime": "NewTime",
           "ProcessId": "ProcessId",  # Win 7+
           "ProcessName": "ProcessPath"},  # Win 7+

    4624: {"Descr": "An account was successfully logged on",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonId": "TargetLogonId",
           "LogonType": "+LogonType",
           "WorkstationName": "WorkstationName",
           "LogonGuid": "LogonGUID",
           "TransmittedServices": "TransmittedServices",
           "IpAddress": "IP",
           "IpPort": "Port",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath",
           "AuthenticationPackageName": "AuthenticationPackage",
           "LogonProcessName": "LogonProcess",
           "KeyLength": "KeyLength",
           "RestrictedAdminMode": "RestrictedAdminMode",  # Win 10+
           "ElevatedToken": "ElevatedToken",  # Win 10+
           "TargetOutboundUserName": "TargetOutboundUsername",
           "TargetOutboundDomainName": "TargetOutboundDomain"},

    4625: {"Descr": "An account failed to log on",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "LogonType": "+LogonType",
           "WorkstationName": "WorkstationName",
           "IpAddress": "IP",
           "IpPort": "Port",
           "LogonProcessName": "LogonProcessName",
           "Status": "+Status",
           "FailureReason": "FailureReason",  # %% format
           "SubStatus": "SubStatus",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

    4627: {"Descr": "Group membership information",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "LogonType": "+LogonType",
           "GroupMembership": "GroupMembership"},  # to convert

    4634: {"Descr": "An account was logged off",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonId": "TargetLogonId",
           "LogonType": "+LogonType"},

    4647: {"Descr": "User initiated logoff",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonId": "TargetLogonId"},

    4648: {"Descr": "A logon was attempted using explicit credentials",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "LogonGuid": "LogonGUID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonGuid": "TargetLogonGuid",
           "TargetServerName": "TargetServerName",
           "TargetInfo": "TargetInfo",
           "IpAddress": "IP",
           "IpPort": "Port",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

    4657: {"Descr": "A registry value was modified",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectName": "RegKey",
           "ObjectValueName": "RegValue",
           "OperationType": "OperationType",
           "OldValueType": "OldValueType",
           "OldValue": "OldValue",
           "NewValueType": "NewValueType",
           "NewValue": "NewValue",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

    4661: {"Descr": "A handle to an object was requested",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectServer": "ObjectServer",
           "ObjectType": "ObjectType",
           "ObjectName": "ObjectName",
           "HandleId": "HandleId",
           "TransactionId": "TransactionId",
           "AccessList": "AccessList",  # %% format
           "AccessMask": "AccessMask",  # alternate representation of AccessList
           "PrivilegeList": "PrivilegeList",
           "Properties": "Properties",
           "RestrictedSidCount": "RestrictedSidCount",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

    4662: {"Descr": "An operation was performed on an object",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectServer": "ObjectServer",
           "ObjectType": "ObjectType",
           "ObjectName": "ObjectName",
           "OperationType": "OperationType",
           "HandleId": "HandleId",
           "AccessList": "AccessList",  # %% format
           "AccessMask": "AccessMask",  # alternate representation of AccessList
           "Properties": "Properties"},

    4663: {"Descr": "An attempt was made to access an object",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectServer": "ObjectServer",
           "ObjectType": "ObjectType",
           "ObjectName": "ObjectName",
           "HandleId": "HandleId",
           "AccessList": "AccessList",  # %% format
           "AccessMask": "AccessMask",  # alternate representation of AccessList
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath",
           "ResourceAttributes": "ResourceAttributes"},

    4672: {"Descr": "Special privileges assigned to new logon",
           "SubjectUserSid": "TargetSID",
           "SubjectUserName": "TargetUsername",
           "SubjectDomainName": "TargetDomain",
           "SubjectLogonId": "TargetLogonId",
           "PrivilegeList": "PrivilegeList"},

    4673: {"Descr": "A privileged service was called",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectServer": "ObjectServer",
           "Service": "Service",
           "PrivilegeList": "PrivilegeList",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

    4688: {"Descr": "A new process has been created",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "NewProcessId": "NewProcessId",
           "NewProcessName": "NewProcessPath",
           "TokenElevationType": "TokenElevationType",  # %% format
           "CommandLine": "Command",  # Win 8.1+
           "ProcessId": "ProcessId",
           # Win 10+
           "ParentProcessName": "ProcessPath",
           "MandatoryLabel": "+MandatoryLabel",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonId": "TargetLogonId"},

    4697: {"Descr": "A service was installed in the system",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ServiceName": "ServiceName",
           "ServiceFileName": "ServicePath",
           "ServiceType": "+ServiceType",
           "ServiceStartType": "+ServiceStartType",
           "ServiceAccount": "Username"},

    4698: {"Descr": "A scheduled task was created",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContent": "TaskContent"},

    4699: {"Descr": "A scheduled task was deleted",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContent": "TaskContent"},

    4700: {"Descr": "A scheduled task was enabled",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContent": "TaskContent"},

    4701: {"Descr": "A scheduled task was disabled",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContent": "TaskContent"},

    4702: {"Descr": "A scheduled task was updated",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContentNew": "TaskContent"},

    4719: {"Descr": "System audit policy was changed",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "CategoryId": "CategoryId",  # %% format
           "SubcategoryId": "SubcategoryId",  # %% format
           "SubcategoryGuid": "SubcategoryGuid",  # %% format
           "AuditPolicyChanges": "AuditPolicyChanges"},  # %% format (multiple, joined with ', ')

    4720: {"Descr": "A user account was created",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "PrivilegeList": "PrivilegeList",
           "SamAccountName": "SamAccountName",
           "DisplayName": "DisplayName",
           "UserPrincipalName": "UserPrincipalName",
           "HomeDirectory": "HomeDirectory",
           "HomePath": "HomePath",
           "ScriptPath": "ScriptPath",
           "ProfilePath": "ProfilePath",
           "UserWorkstations": "UserWorkstations",
           "PasswordLastSet": "PasswordLastSet",
           "AccountExpires": "AccountExpires",
           "PrimaryGroupId": "PrimaryGroupId",
           "AllowedToDelegateTo": "AllowedToDelegateTo",
           "OldUacValue": "OldUacValue",
           "SidHistory": "SIDHistory",
           "LogonHours": "LogonHours",
           "UserAccountControl": "UserAccountControl"},  # %% format (multiple, joined with ' ')

    4726: {"Descr": "A user account was deleted",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain"},

    4728: {"Descr": "A member was added to a security-enabled global group",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "MemberSid": "TargetSID",
           "MemberName": "TargetUsername",
           "TargetSid": "TargetGroupSID",
           "TargetUserName": "TargetGroup",
           "TargetDomainName": "TargetDomain",
           "PrivilegeList": "PrivilegeList"},

    4732: {"Descr": "A member was added to a security-enabled local group",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "MemberSid": "TargetSID",
           "MemberName": "TargetUsername",
           "TargetSid": "TargetGroupSID",
           "TargetUserName": "TargetGroup",
           "TargetDomainName": "TargetDomain",
           "PrivilegeList": "PrivilegeList"},

    4738: {"Descr": "A user account was changed",  # non-changed values are -
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "PrivilegeList": "PrivilegeList",
           "SamAccountName": "SamAccountName",
           "DisplayName": "DisplayName",
           "UserPrincipalName": "UserPrincipalName",
           "HomeDirectory": "HomeDirectory",
           "HomePath": "HomePath",
           "ScriptPath": "ScriptPath",
           "ProfilePath": "ProfilePath",
           "UserWorkstations": "UserWorkstations",
           "PasswordLastSet": "PasswordLastSet",
           "AccountExpires": "AccountExpires",
           "PrimaryGroupId": "PrimaryGroupId",
           "AllowedToDelegateTo": "AllowedToDelegateTo",
           "OldUacValue": "OldUacValue",  # to convert
           "NewUacValue": "NewUacValue",  # to convert
           "UserParameters": "UserParameters",
           "SidHistory": "SIDHistory",
           "LogonHours": "LogonHours",
           "UserAccountControl": "UserAccountControl"},  # %% format

    4740: {"Descr": "A user account was locked out",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain"},

    4741: {"Descr": "A computer account was created",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "PrivilegeList": "PrivilegeList",
           "SamAccountName": "SamAccountName",
           "DisplayName": "DisplayName",
           "UserPrincipalName": "UserPrincipalName",
           "HomeDirectory": "HomeDirectory",
           "HomePath": "HomePath",
           "ScriptPath": "ScriptPath",
           "ProfilePath": "ProfilePath",
           "UserWorkstations": "UserWorkstations",
           "PasswordLastSet": "PasswordLastSet",
           "AccountExpires": "AccountExpires",
           "PrimaryGroupId": "PrimaryGroupId",
           "AllowedToDelegateTo": "AllowedToDelegateTo",
           "OldUacValue": "OldUacValue",  # to convert
           "NewUacValue": "NewUacValue",  # to convert
           "UserParameters": "UserParameters",
           "SidHistory": "SIDHistory",
           "LogonHours": "LogonHours",
           "UserAccountControl": "UserAccountControl",  # %% format
           "DnsHostName": "Hostname",
           "ServicePrincipalNames": "SPNs"},

    4768: {"Descr": "A Kerberos authentication ticket (TGT) was requested",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "ServiceSid": "ServiceSID",
           "ServiceName": "ServiceName",
           "TicketOptions": "+TicketOptions",
           "Status": "+ResultCode",
           "TicketEncryptionType": "+TicketEncryptionType",
           "PreAuthType": "+PreAuthType",
           "IpAddress": "IP",
           "IpPort": "Port",
           "CertIssuerName": "CertIssuer",
           "CertSerialNumber": "CertSerialNumber",
           "CertThumbprint": "CertThumbprint"},

    4769: {"Descr": "A Kerberos service ticket was requested",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "ServiceSid": "ServiceSID",
           "ServiceName": "ServiceName",
           "TicketOptions": "+TicketOptions",
           "Status": "+ResultCode",
           "TicketEncryptionType": "+TicketEncryptionType",
           "PreAuthType": "+PreAuthType",
           "IpAddress": "IP",
           "IpPort": "Port",
           "LogonGuid": "LogonGUID",
           "TransmittedServices": "TransmittedServices"},

    4771: {"Descr": "Kerberos pre-authentication failed",
           "TargetUserName": "TargetUsername",
           "TargetSid": "TargetSID",
           "ServiceName": "ServiceName",
           "TicketOptions": "+TicketOptions",
           "Status": "+ResultCode",
           "PreAuthType": "+PreAuthType",
           "IpAddress": "IP",
           "IpPort": "Port"},

    4776: {"Descr": "The computer attempted to validate the credentials for an account",
           "TargetUserName": "TargetUsername",
           "Workstation": "WorkstationName",
           "PackageName": "AuthenticationPackage",
           "Status": "+ResultCode"},

    4778: {"Descr": "A session was reconnected to a Window Station",
           "AccountName": "TargetUsername",
           "AccountDomain": "TargetDomain",
           "LogonID": "TargetLogonId",
           "SessionName": "SessionName",
           "ClientName": "WorkstationName",
           "ClientAddress": "IP",
           "PackageName": "AuthenticationPackage"},

    4779: {"Descr": "A session was disconnected from a Window Station",
           "AccountName": "TargetUsername",
           "AccountDomain": "TargetDomain",
           "LogonID": "TargetLogonId",
           "SessionName": "SessionName",
           "ClientName": "WorkstationName",
           "ClientAddress": "IP"},

    4798: {"Descr": "A user's local group membership was enumerated",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetSid": "TargetSID",
           "CallerProcessId": "ProcessId",
           "CallerProcessName": "ProcessPath"},

    4799: {"Descr": "A security-enabled local group membership was enumerated",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetSid": "TargetSID",
           "CallerProcessId": "ProcessId",
           "CallerProcessName": "ProcessPath"},

    4825: {"Descr": "A user was denied the access to Remote Desktop. By default, users are allowed to connect only "
                    "if they are members of the Remote Desktop Users group or Administrators group",
           "AccountName": "TargetUsername",
           "AccountDomain": "TargetDomain",
           "LogonID": "TargetLogonId",
           "ClientAddress": "IP"},

    5059: {"Descr": "Key migration operation",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ProviderName": "ProviderName",
           "AlgorithmName": "AlgorithmName",
           "KeyName": "KeyName",
           "KeyType": "KeyType",
           "Operation": "OperationType",
           "ReturnCode": "ResultCode"},

    5140: {"Descr": "A network share object was accessed",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectType": "ObjectType",
           "ShareName": "ShareName",
           "ShareLocalPath": "ShareLocalPath",
           "IpAddress": "IP",
           "IpPort": "Port",
           "AccessList": "AccessList"},  # %% format

    5142: {"Descr": "A network share object was added",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ShareName": "ShareName",
           "ShareLocalPath": "ShareLocalPath"},

    5144: {"Descr": "A network share object was deleted",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ShareName": "ShareName",
           "ShareLocalPath": "ShareLocalPath"},

    5145: {"Descr": "A network share object was checked to see whether client can be granted desired access",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectType": "ObjectType",
           "ShareName": "ShareName",
           "ShareLocalPath": "ShareLocalPath",
           "RelativeTargetName": "RelativeTargetName",
           "IpAddress": "IP",
           "IpPort": "Port",
           "AccessList": "AccessList",  # %% format
           "AccessMask": "AccessMask",  # alternate representation of AccessList
           "AccessReason": "AccessReason"},

    5152: {"Descr": "The Windows Filtering Platform has blocked a packet",
           "ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "SourceAddress": "IP",
           "SourcePort": "Port",
           "DestAddress": "TargetIP",
           "DestPort": "TargetPort",
           "Protocol": "+Protocol"},

    5156: {"Descr": "The Windows Filtering Platform has permitted a connection",
           "ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "IpAddress": "IP",
           "IpPort": "Port",
           "DestAddress": "TargetIP",
           "DestPort": "TargetPort",
           "Protocol": "+Protocol",
           "RemoteUserID": "TargetSID",
           "RemoteMachineID": "TargetMachineSID"},

    5158: {"Descr": "The Windows Filtering Platform has permitted a bind to a local port",
           "ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "SourceAddress": "IP",
           "SourcePort": "Port",
           "Protocol": "+Protocol"},

    6416: {"Descr": "A new external device was recognized by the System",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "DeviceId": "DeviceName",  # Win10 v1511+
           "DeviceDescription": "DeviceDescr",  # Win10 v1511+
           "ClassId": "ClassId",  # Win10 v1511+
           "ClassName": "ClassName",  # Win10 v1511+
           "VendorIds": "VendorId",
           "CompatibleIds": "CompatibleId",
           "LocationInformation": "Location"}
}

sys = {  # System
    # Provider: Microsoft-Windows-Audit-CVE
    2: {"Descr": "Possible detection of CVE: <CVEId>. This event is raised by a kernel mode driver",
        "CVEID": "CVEID",
        "AdditionalDetails": "AdditionalDetails"},

    104: {"Descr": "The <EventLogName> log file was cleared",
          "SubjectUserName": "Username",
          "SubjectDomainName": "Domain",
          "Channel": "EventLogName",
          "BackupPath": "BackupPath"},

    1014: {"Descr": "Name resolution for the <QueryName> timed out after none of the configured DNS servers responded",
           "QueryName": "QueryName",
           "Address": "Address"},

    # Provider: Microsoft-Windows-Diagnostics-Networking
    6100: {"Descr": "Details about Networking <HelperClassName> diagnosis:",
           "HelperClassName": "HelperClassName",
           "EventDescription": "EventDescr",
           "EventVerbosity": "EventVerbosity"},

    7034: {"Descr": "The <ServiceName> terminated unexpectedly. It has done this <Count> time(s)",
           "param1": "ServiceName",
           "param2": "Count"},

    7035: {"Descr": "The <ServiceName> was successfully sent a <Control>",
           "param1": "ServiceName",
           "param2": "Control"},

    7036: {"Descr": "The <ServiceName> entered the <StatusAfter> state",
           "param1": "ServiceName",
           "param2": "StatusAfter"},

    7040: {"Descr": "The start type of <ServiceName> was changed from <StatusBefore> to <StatusAfter>",
           "param1": "ServiceName",
           "param2": "StatusBefore",
           "param3": "StatusAfter"},

    7045: {"Descr": "A service was installed on the system",
           "ServiceName": "ServiceName",
           "ImagePath": "ServicePath",
           "ServiceType": "ServiceType",
           "StartType": "StartType",
           "AccountName": "Username"},

    9009: {"Descr": "The Desktop Window Manager has exited with code <ExitCode>",  # classic event, incorrect channel?
           "Param1": "ExitCode"},

    # Provider: Microsoft-Windows-DriverFrameworks-UserMode
    10000: {"Descr": "A driver package which uses user-mode driver framework version <FrameworkVersion> is being "
                     "installed on device <DeviceId>",
            "DeviceId": "DeviceId",
            "FrameworkVersion": "FrameworkVersion"},

    # Provider: Microsoft-Windows-UserPnp
    20001: {"Descr": "Driver Management concluded the process to install <DriverName> for <DeviceInstanceId> "
                     "with <Status>",
            "DriverName": "DriverName",
            "DriverVersion": "DriverVersion",
            "DriverProvider": "DriverProvider",
            "DeviceInstanceID": "DeviceInstanceID",
            "DriverDescription": "DriverDescr",
            "SetupClass": "SetupClass",
            "RebootOption": "RebootOption",
            "UpgradeDevice": "UpgradeDevice",
            "IsDriverOEM": "IsDriverOEM",
            "InstallStatus": "Status"},

    # Provider: Microsoft-Windows-UserPnp
    20002: {"Descr": "Driver Management concluded the process to remove <DriverName> from <DeviceInstanceId> "
                     "with <Status>",
            "DriverName": "DriverName",
            "DriverVersion": "DriverVersion",
            "DriverProvider": "DriverProvider",
            "DeviceInstanceID": "DeviceInstanceID",
            "DriverDescription": "DriverDescr",
            "SetupClass": "SetupClass",
            "RebootOption": "RebootOption",
            "UpgradeDevice": "UpgradeDevice",
            "IsDriverOEM": "IsDriverOEM",
            "InstallStatus": "Status"},

    # Provider: Microsoft-Windows-UserPnp
    20003: {"Descr": "Driver Management has concluded the process to add <ServiceName>> for <DeviceInstanceID> "
                     "with <Status>",
            "ServiceName": "DriverName",
            "DriverFileName": "DriverPath",
            "DeviceInstanceID": "DeviceInstanceID",
            "PrimaryService": "IsPrimaryService",
            "IsUpdateService": "IsUpdateService",
            "AddServiceStatus": "AddServiceStatus"}
}

app = {  # Application
    # Provider: Microsoft-Windows-Audit-CVE
    1: {"Descr": "Possible detection of CVE: <CVEId>. This event is raised by a User mode process",
        "CVEID": "CVEID",
        "AdditionalDetails": "AdditionalDetails"},

    # Provider: ESENT
    216: {"Descr": "%1 (%2) %3 A database location change was detected from %4 to %5"},

    # Provider: ESENT
    325: {"Descr": "%1 (%2) %3 The database engine created a new database (%4, %5). (Time=%6 seconds)"},

    # Provider: ESENT
    326: {"Descr": "%1 (%2) %3 The database engine attached a database (%4, %5). (Time=%6 seconds)"},

    # Provider: ESENT
    327: {"Descr": "%1 (%2) %3 The database engine detached a database (%4, %5). (Time=%6 seconds)"},

    # Provider: Windows Error Reporting
    1001: {"Descr": "Process Error"}
}

appexp1 = {  # Microsoft-Windows-Application-Experience/Program-Inventory
    800: {"Descr": "An instance of Program Data Updater (PDU) ran with the following information...",  # Win7 - 8.1
          "StartTime": "StartTime",
          "StopTime": "StopTime",
          "ExitCode": "ExitCode",
          "NumNewPrograms": "NumNewPrograms",
          "NumRemovedPrograms": "NumRemovedPrograms",
          "NumUpdatedPrograms": "NumUpdatedPrograms",
          "NumInstalledPrograms": "NumInstalledPrograms",
          "NumNewOrphans": "NumNewOrphans",
          "NumNewAddOns": "NumNewAddOns",
          "NumRemovedAddOns": "NumRemovedAddOns",
          "NumUpdatedAddOns": "NumUpdatedAddOns",
          "NumInstalledAddOns": "NumInstalledAddOns",
          "NumNewInstallations": "NumNewInstallations"}
}

appexp2 = {  # Microsoft-Windows-Application-Experience/Program-Telemetry
    500: {"Descr": "Compatibility fix applied to <ProcessPath>.  Fix information: <FixName>, <FixId>, <Flags>",
          "ProcessId": "ProcessId",
          "ExePath": "ProcessPath",
          "StartTime": "StartTime",
          "FixID": "FixId",
          "FixName": "FixName",
          "Flags": "Flags"},

    501: {"Descr": "Compatibility fix applied to <ProcessPath>.  Fix information: <FixName>, <FixId>, <Flags>",
          "ProcessId": "ProcessId",
          "ExePath": "ProcessPath",
          "StartTime": "StartTime",
          "FixID": "FixId",
          "FixName": "FixName",
          "Flags": "Flags"},

    502: {"Descr": "Compatibility fix applied to <MsiPath>.  Fix information: <FixName>, <FixId>, <Flags>",
          "ClientProcessId": "ProcessId",
          "ClientStartTime": "StartTime",
          "FixID": "FixId",
          "FixName": "FixName",
          "Flags": "Flags",
          "ProductCode": "ProductCode",
          "PackageCode": "PackageCode",
          "MsiPath": "MsiPath"},

    503: {"Descr": "Compatibility fix applied to <MsiPath>.  Fix information: <FixName>, <FixId>, <Flags>",
          "ClientProcessId": "ProcessId",
          "ClientStartTime": "StartTime",
          "FixID": "FixId",
          "FixName": "FixName",
          "Flags": "Flags",
          "ProductCode": "ProductCode",
          "PackageCode": "PackageCode",
          "MsiPath": "MsiPath"}
}

applocker = {  # Microsoft-Windows-AppLocker/EXE and DLL
    8004: {"Descr": "<FilePath> was prevented from running",
           "PolicyNameBuffer": "Policy",
           "RuleId": "RuleId",
           "RuleNameBuffer": "RuleName",
           "RuleSddlBuffer": "RuleSddl",
           "TargetUser": "TargetUsername",
           "TargetLogonId": "TargetLogonId",
           "TargetProcessId": "TargetProcessId",
           "FilePathBuffer": "FilePath",
           "FileHash": "FileHash",
           "Fqbn": "Fqbn"}
}

bits = {  # Microsoft-Windows-Bits-Client/Operational
    # Provider: Microsoft-Windows-Bits-Client
    4: {"Descr": "The transfer job is complete",
        "User": "Username",
        "jobTitle": "JobTitle",
        "jobId": "JobId",
        "jobOwner": "JobOwner",
        "fileCount": "FileCount"},

    59: {"Descr": "BITS started the <Name> transfer job that is associated with the <URL>",
         "transferId": "TransferId",
         "name": "Name",
         "Id": "JobId",
         "url": "URL",
         "peer": "Peer",
         "fileTime": "FileTime",
         "fileLength": "FileSize"},

    60: {"Descr": "BITS stopped transferring the <Name> transfer job that is associated with the <URL>",
         "transferId": "TransferId",
         "name": "Name",
         "Id": "JobId",
         "url": "URL",
         "peer": "Peer",
         "fileTime": "FileTime",
         "fileLength": "FileSize",
         "bytesTotal": "BytesTotal",
         "bytesTransferred": "BytesTransferred",
         "bytesTransferredFromPeer": "BytesTransferredFromPeer"}
}

codeinteg = {  # Microsoft-Windows-CodeIntegrity/Operational
    # Provider: Microsoft-Windows-CodeIntegrity
    3001: {"Descr": "Code Integrity determined an unsigned kernel module <FileName> is loaded into the system",
           "FileNameBuffer": "FileName"}
}

diag = {  # Microsoft-Windows-Diagnostics-Performance/Operational
    100: {"Descr": "Windows has started up",
          "BootStartTime": "BootStartTime",
          "BootEndTime": "BootEndTime",
          "SystemBootInstance": "SystemBootInstance",
          "UserBootInstance": "UserBootInstance",
          "BootTime": "BootTime",  # in milliseconds
          "UserLogonWaitDuration": "UserLogonWaitDuration"},

    200: {"Descr": "Windows has shutdown",
          "ShutdownStartTime": "ShutdownStartTime",
          "ShutdownEndTime": "ShutdownEndTime",
          "ShutdownTime": "ShutdownTime"}  # in milliseconds
}

dnsclient = {  # Microsoft-Windows-DNS-Client/Operational (disabled by default)
    # Provider: Microsoft-Windows-DNS-Client
    1014: {"Descr": "Name resolution for the <QueryName> timed out after none of the configured "
                    "DNS servers responded",
           "QueryName": "QueryName",
           "Address": "Address"},

    # Provider: Microsoft-Windows-DNS-Client
    3006: {"Descr": "DNS query is called for the <QueryName>, <QueryType>",
           "QueryName": "QueryName",
           "QueryType": "+QueryType",
           "QueryOptions": "QueryOptions",
           "ServerList": "ServerList",
           "IsNetworkQuery": "IsNetworkQuery",
           "NetworkQueryIndex": "NetworkIndex",
           "InterfaceIndex": "InterfaceIndex",
           "IsAsyncQuery": "IsAsyncQuery"},

    # Provider: Microsoft-Windows-DNS-Client
    3008: {"Descr": "DNS query is completed for the <QueryName>, <QueryType> with <ResponseCode> <QueryResults>",
           "QueryName": "QueryName",
           "QueryType": "+QueryType",
           "QueryOptions": "QueryOptions",
           "QueryStatus": "ResponseCode",
           "QueryResults": "QueryResults"},

    # Provider: Microsoft-Windows-DNS-Client
    3011: {"Descr": "Received response from <DnsServerIP> for <QueryName> and <QueryType> with <ResponseCode>",
           "QueryName": "QueryName",
           "QueryType": "+QueryType",
           "DnsServerIpAddress": "DnsServerIP",
           "ResponseStatus": "Status"},

    # Provider: Microsoft-Windows-DNS-Client
    3016: {"Descr": "Cache lookup called for <QueryName>, <QueryType>",
           "QueryName": "QueryName",
           "QueryType": "+QueryType",
           "QueryOptions": "QueryOptions",
           "InterfaceIndex": "InterfaceIndex"},

    # Provider: Microsoft-Windows-DNS-Client
    3018: {"Descr": "Cache lookup for <QueryName>, <QueryType> returned <ResponseCode> with <QueryResults>",
           "QueryName": "QueryName",
           "QueryType": "+QueryType",
           "QueryOptions": "QueryOptions",
           "Status": "ResponseCode",
           "QueryResults": "QueryResults"},

    # Provider: Microsoft-Windows-DNS-Client
    3019: {"Descr": "Query wire called for name <QueryName>, <QueryType>",
           "QueryName": "QueryName",
           "QueryType": "+QueryType",
           "NetworkIndex": "NetworkIndex",
           "InterfaceIndex": "InterfaceIndex"},

    # Provider: Microsoft-Windows-DNS-Client
    3020: {"Descr": "Query response for name <QueryName>, <QueryType> returned <ResponseCode> with <QueryResults>",
           "QueryName": "QueryName",
           "QueryType": "+QueryType",
           "NetworkIndex": "NetworkIndex",
           "InterfaceIndex": "InterfaceIndex",
           "Status": "ResponseCode",
           "QueryResults": "QueryResults"}
}

dnsserver = {  # Microsoft-Windows-DNSServer/Analytical (Windows Server 2016+)
    256: {"Descr": "Query received",
          "TCP": "TCP",
          "InterfaceIP": "InterfaceIP",
          "Source": "Source",
          "RD": "RD",
          "QNAME": "QueryName",
          "QTYPE": "QueryType",
          "XID": "XID",
          "Port": "Port",
          "Flags": "Flags",
          "PacketData": "PacketData",
          "AdditionalInfo": "AdditionalInfo"},

    257: {"Descr": "Response success",
          "TCP": "TCP",
          "InterfaceIP": "InterfaceIP",
          "Destination": "Destination",
          "AA": "AA",
          "AD": "AD",
          "QNAME": "QueryName",
          "QTYPE": "QueryType",
          "XID": "XID",
          "DNSSEC": "DNSSEC",
          "RCODE": "RCode",
          "Port": "Port",
          "Flags": "Flags",
          "Scope": "Scope",
          "Zone": "Zone",
          "PolicyName": "Policy",
          "PacketData": "PacketData",
          "AdditionalInfo": "AdditionalInfo"},

    258: {"Descr": "Response failure",
          "TCP": "TCP",
          "InterfaceIP": "InterfaceIP",
          "Reason": "Reason",
          "Destination": "Destination",
          "QNAME": "QueryName",
          "QTYPE": "QueryType",
          "XID": "XID",
          "RCODE": "RCode",
          "Port": "Port",
          "Flags": "Flags",
          "Zone": "Zone",
          "PolicyName": "Policy",
          "PacketData": "PacketData",
          "AdditionalInfo": "AdditionalInfo"},

    259: {"Descr": "Ignored query",
          "TCP": "TCP",
          "InterfaceIP": "InterfaceIP",
          "Source": "Source",
          "Reason": "Reason",
          "QNAME": "QueryName",
          "QTYPE": "QueryType",
          "XID": "XID",
          "Zone": "Zone",
          "PolicyName": "Policy",
          "AdditionalInfo": "AdditionalInfo"},

    260: {"Descr": "Recurse query out",
          "TCP": "TCP",
          "InterfaceIP": "InterfaceIP",
          "Destination": "Destination",
          "RD": "RD",
          "QNAME": "QueryName",
          "QTYPE": "QueryType",
          "XID": "XID",
          "Port": "Port",
          "Flags": "Flags",
          "RecursionScope": "RecursionScope",
          "CacheScope": "CacheScope",
          "PolicyName": "Policy",
          "PacketData": "PacketData",
          "AdditionalInfo": "AdditionalInfo"},

    261: {"Descr": "Recurse response in",
          "TCP": "TCP",
          "InterfaceIP": "InterfaceIP",
          "Source": "Source",
          "AA": "AA",
          "AD": "AD",
          "QNAME": "QueryName",
          "QTYPE": "QueryType",
          "XID": "XID",
          "Port": "Port",
          "Flags": "Flags",
          "RecursionScope": "RecursionScope",
          "CacheScope": "CacheScope",
          "PacketData": "PacketData",
          "AdditionalInfo": "AdditionalInfo"},

    262: {"Descr": "Recurse query timeout",
          "TCP": "TCP",
          "InterfaceIP": "InterfaceIP",
          "Destination": "Destination",
          "QNAME": "QueryName",
          "QTYPE": "QueryType",
          "XID": "XID",
          "Port": "Port",
          "Flags": "Flags",
          "RecursionScope": "RecursionScope",
          "CacheScope": "CacheScope",
          "AdditionalInfo": "AdditionalInfo"}
}

driverfw = {  # Microsoft-Windows-DriverFrameworks-UserMode/Operational
    2003: {"Descr": "The UMDF Host Process (<HostProcessId>) has been asked to load drivers for device <DeviceId>",
           "LifetimeId": "HostProcessId",
           "InstanceId": "DeviceId"},

    2004: {"Descr": "The UMDF Host is loading <Driver> at <Level> for device <DeviceId>",
           "LifetimeId": "HostProcessId",
           "InstanceId": "DeviceId",
           "Level": "Level",
           "Service": "Driver",
           "ClsId": "DriverClassId"},

    2005: {"Descr": "The UMDF Host Process (<HostProcessId>) has loaded <ModulePath> while loading drivers for device "
                    "<DeviceId>",
           "LifetimeId": "HostProcessId",
           "InstanceId": "DeviceId",
           "ModulePath": "ModulePath",
           "CompanyName": "CompanyName",
           "FileDescription": "FileDescr",
           "FileVersion": "FileVersion"},

    2010: {"Descr": "The UMDF Host Process (<HostProcessId>) has successfully loaded drivers for device <DeviceId>",
           "LifetimeId": "HostProcessId",
           "InstanceId": "DeviceId",
           "FinalStatus": "FinalStatus"},

    2100: {"Descr": "Received a Pnp or Power operation (<MajorCode>, <MinorCode>) for device <DeviceId>",
           "LifetimeId": "HostProcessId",
           "InstanceId": "DeviceId",
           "MajorCode": "MajorCode",
           "MinorCode": "MinorCode",
           "Status": "Status"},

    2102: {"Descr": "Forwarded a finished Pnp or Power operation (<MajorCode>, <MinorCode>) to the lower driver "
                    "for device <DeviceId> with <Status>",
           "LifetimeId": "HostProcessId",
           "InstanceId": "DeviceId",
           "MajorCode": "MajorCode",
           "MinorCode": "MinorCode",
           "Status": "Status"},

    2105: {"Descr": "Forwarded a Pnp or Power operation (<MajorCode>, <MinorCode>) for device <DeviceId> to the "
                    "lower driver with <Status>",
           "LifetimeId": "HostProcessId",
           "InstanceId": "DeviceId",
           "MajorCode": "MajorCode",
           "MinorCode": "MinorCode",
           "Status": "Status"}
}

fwall = {  # Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
    2004: {"Descr": "A rule has been added to the Windows Firewall exception list",
           "RuleId": "RuleId",
           "RuleName": "RuleName",
           "Origin": "+Origin",
           "ApplicationPath": "ApplicationPath",
           "ServiceName": "ServiceName",
           "Direction": "+Direction",
           "Protocol": "+Protocol",
           "LocalPorts": "TargetPort",
           "RemotePorts": "RemotePorts",
           "Action": "+Action",
           "Profiles": "+Profiles",
           "LocalAddresses": "TargetIP",
           "EmbeddedContext": "EmbeddedContext",
           "Active": "+Active",
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"},

    2005: {"Descr": "A rule has been modified in the Windows Firewall exception list",
           "RuleId": "RuleId",
           "RuleName": "RuleName",
           "Origin": "+Origin",
           "ApplicationPath": "ApplicationPath",
           "ServiceName": "ServiceName",
           "Direction": "+Direction",
           "Protocol": "+Protocol",
           "LocalPorts": "TargetPort",
           "RemotePorts": "RemotePorts",
           "Action": "+Action",
           "Profiles": "+Profiles",
           "LocalAddresses": "TargetIP",
           "EmbeddedContext": "EmbeddedContext",
           "Active": "+Active",
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"},

    2006: {"Descr": "A rule has been deleted in the Windows Firewall exception list",
           "RuleId": "RuleId",
           "RuleName": "RuleName",
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"}
}

kernelpnp = {  # Microsoft-Windows-Kernel-PnP/Configuration
    400: {"Descr": "<DeviceInstanceId> was configured",
          "DeviceInstanceId": "DeviceInstanceId",
          "DriverName": "DriverName",
          "ClassGuid": "+ClassName",
          "DriverDate": "DriverDate",
          "DriverVersion": "DriverVersion",
          "DriverProvider": "DriverProvider",
          "DriverInbox": "IsDriverInbox",
          "DriverSection": "DriverSection",
          "DeviceId": "DeviceId",
          "OutrankedDrivers": "OutrankedDrivers",
          "DeviceUpdated": "IsDeviceUpdated",
          "Status": "Status",
          "ParentDeviceInstanceId": "ParentDeviceInstanceId"},

    410: {"Descr": "<DeviceInstanceId> was started",
          "DeviceInstanceId": "DeviceInstanceId",
          "DriverName": "DriverName",
          "ClassGuid": "+ClassName",
          "ServiceName": "ServiceName",
          "LowerFilters": "LowerFilters",
          "UpperFilters": "UpperFilters",
          "Problem": "Problem",
          "Status": "Status"},

    430: {"Descr": "<DeviceInstanceId> requires further installation",
          "DeviceInstanceId": "DeviceInstanceId"}
}

lsm = {  # Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    21: {"Descr": "Remote Desktop Services: Session logon succeeded",
         "User": "TargetUsername",
         "SessionID": "TargetSessionId",
         "Address": "IP"},

    22: {"Descr": "Remote Desktop Services: Shell start notification received",
         "User": "TargetUsername",
         "SessionID": "TargetSessionId",
         "Address": "IP"},

    23: {"Descr": "Remote Desktop Services: Session logoff succeeded",
         "User": "TargetUsername",
         "SessionID": "TargetSessionId"},

    24: {"Descr": "Remote Desktop Services: Session has been disconnected",
         "User": "TargetUsername",
         "SessionID": "TargetSessionId",
         "Address": "IP"},

    25: {"Descr": "Remote Desktop Services: Session reconnection succeeded",
         "User": "TargetUsername",
         "SessionID": "TargetSessionId",
         "Address": "IP"},

    39: {"Descr": "<TargetSessionId> has been disconnected by session <SessionId>",
         "TargetSession": "TargetSessionId",
         "Source": "SessionId"},

    40: {"Descr": "<TargetSessionId> has been disconnected, <Reason>",
         "Session": "TargetSessionId",
         "Reason": "+Reason"},

    41: {"Descr": "Begin session arbitration",  # Win8.1+
         "User": "TargetUsername",
         "SessionID": "TargetSessionId"}
}

ntfs = {  # Microsoft-Windows-Ntfs/Operational
    # Provider: Microsoft-Windows-Ntfs
    142: {"Descr": "Summary of disk space usage, since last event",
          "VolumeGuid": "VolumeGuid",
          "VolumeName": "VolumeName",
          "LowestFreeSpaceInBytes": "LowestFreeSpaceInBytes",
          "HighestFreeSpaceInBytes": "HighestFreeSpaceInBytes",
          "IsBootVolume": "IsBootVolume"},

    # Provider: Microsoft-Windows-Ntfs
    145: {"Descr": "IO latency summary common data for volume",
          "VolumeCorrelationId": "VolumeGuid",
          "VolumeName": "VolumeName",
          "IsBootVolume": "IsBootVolume"}
}

offlinef = {  # Microsoft-Windows-OfflineFiles/Operational
    7: {"Descr": "User logon detected: <Username> <Session>",
        "Account": "TargetUsername",
        "Session": "TargetSessionId"},

    8: {"Descr": "User logoff detected: <Username> <Session>",
        "Account": "TargetUsername",
        "Session": "TargetSessionId"}
}

partition = {  # Microsoft-Windows-Partition/Diagnostic; Win10 v1709+
    1006: {"Descr": "A device is connected or disconnected from the system",
           "Version": "Version",
           "DiskNumber": "DiskNumber",
           "Flags": "Flags",
           "Characteristics": "Characteristics",
           "BytesPerSector": "BytesPerSector",
           "BytesPerLogicalSector": "BytesPerLogicalSector",
           "BytesPerPhysicalSector": "BytesPerPhysicalSector",
           "BytesOffsetForSectorAlignment": "BytesOffsetForSectorAlignment",
           "Capacity": "Capacity",
           "BusType": "+BusType",
           "Manufacturer": "Vendor",
           "Model": "Product",
           "Revision": "ProductRevision",
           "SerialNumber": "SerialNumber",
           "Location": "Location",
           "ParentId": "ParentId",
           "DiskId": "DiskId",
           "AdapterId": "AdapterId",
           "RegistryId": "RegistryId",
           "PoolId": "PoolId",
           "StorageIdType": "+StorageIdType",
           "StorageIdAssociation": "+StorageIdAssoc",
           "StorageId": "StorageId",
           "IsTrimSupported": "IsTrimSupported",
           "IsThinProvisioned": "IsThinProvisioned",
           "HybridSupported": "HybridSupported",
           "HybridCacheBytes": "HybridCacheBytes",
           "AdapterSerialNumber": "AdapterSerialNumber",
           "UserRemovalPolicy": "UserRemovalPolicy",
           "PartitionStyle": "+PartitionStyle",
           "PartitionCount": "PartitionCount",
           "PartitionTableBytes": "PartitionTableBytes",
           "MbrBytes": "MbrBytes",
           "Vbr0Bytes": "Vbr0Bytes",
           "Vbr1Bytes": "Vbr1Bytes",
           "Vbr2Bytes": "Vbr2Bytes",
           "Vbr3Size": "Vbr3Bytes"}
}

printsvc = {  # Microsoft-Windows-PrintService/Operational
    # Provider: Microsoft-Windows-PrintService
    307: {"Descr": "Spooler operation succeeded",
          "param1": "JobId",
          "param2": "JobName",
          "param3": "DocumentOwner",
          "param4": "Host",
          "param5": "PrinterName",
          "param6": "PrinterPort",
          "param7": "Size",
          "param8": "Pages"}
}

pshell1 = {  # Windows PowerShell
    400: {"Descr": "Engine state is changed from <PreviousEngineState> to <NewEngineState>"},  # start of session

    403: {"Descr": "Engine state is changed from <PreviousEngineState> to <NewEngineState>"},  # end of session

    500: {"Descr": "Command <CommandName> is <NewCommandState>"},  # start of execution

    501: {"Descr": "Command <CommandName> is <NewCommandState>"},  # end of execution

    600: {"Descr": "Provider <ProviderName> is <NewProviderState>"},

    800: {"Descr": "Pipeline execution details for command line: <CommandLine>"}
}

pshell2 = {  # Microsoft-Windows-PowerShell/Operational
    4103: {"Descr": "<Payload> Context: <ContextInfo>",  # Module logging
           "UserData": "UserData",
           "Payload": "Payload"},

    4104: {"Descr": "Creating Scriptblock text (<MessageNumber> of <MessageTotal>)",  # Scriptblock module logging
           "MessageNumber": "MessageNumber",
           "MessageTotal": "MessageTotal",
           "ScriptBlockText": "ScriptBlockText",
           "ScriptBlockId": "ScriptBlockId",
           "Path": "Path"},

    8193: {"Descr": "Creating Runspace object",  # Session created
           "param1": "InstanceId"},

    8194: {"Descr": "Creating RunspacePool object",  # Session created
           "InstanceId": "InstanceId",
           "MaxRunspaces": "MaxRunspaces",
           "MinRunspaces": "MinRunspaces"},

    8197: {"Descr": "Runspace state changed to <Status>",  # Session status
           "param1": "Status"},

    40961: {"Descr": "PowerShell console is starting up"},  # empty

    40962: {"Descr": "PowerShell console is ready for user input"},  # empty

    53504: {"Descr": "Windows PowerShell has started an IPC listening thread on <ProcessPath> in <AppDomain>",
            "param1": "ProcessId",
            "param2": "AppDomain"}
}

rcm = {  # Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
    1149: {"Descr": "Remote Desktop Services: User authentication established",
           "Param1": "TargetUsername",
           "Param2": "TargetDomain",
           "Param3": "IP"}
}

rdpclient = {  # Microsoft-Windows-TerminalServices-RDPClient/Operational
    1024: {"Descr": "RDP ClientActiveX is trying to connect to <TargetHost>",
           "Value": "TargetHost"},

    1026: {"Descr": "RDP ClientActiveX has been disconnected: <Reason>",
           "Value": "Reason"},

    1027: {"Descr": "Connected to <TargetDomain> with <TargetSessionId>",
           "DomainName": "TargetDomain",
           "SessionID": "TargetSessionId"},

    1029: {"Descr": "This event is raised during the connection process: Base64(SHA256(<TargetUsername))",
           "TraceMessage": "TargetUsername"},

    1102: {"Descr": "This event is raised during the connection process",
           "Value": "TargetIP"}
}

rdpcorets = {  # Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
    98: {"Descr": "A TCP connection has been successfully established"},

    131: {"Descr": "The server accepted a new <Protocol> connection from <IPPort>",
          "ConnType": "Protocol",
          "ClientIP": "IPPort"},

    # Provider: Microsoft-Windows-RemoteDesktopServices-RdpCoreTS
    148: {"Desc": "<ChannelName> has been closed between the server and the client on transport tunnel <TunnelID>",
          "ChannelName": "ChannelName",
          "TunnelID": "TunnelID"}
}

scpnp = {  # Microsoft-Windows-Storage-ClassPnP/Operational
    # Provider: Microsoft-Windows-StorDiag
    507: {"Descr": "Completing a failed non-ReadWrite SCSI SRB request",
          "DeviceGUID": "DeviceGuid",
          "DeviceNumber": "DeviceNumber",
          "Vendor": "Vendor",
          "Model": "Product",
          "FirmwareVersion": "ProductRevision",
          "SerialNumber": "SerialNumber"}
}

sch = {  # Microsoft-Windows-TaskScheduler/Operational
    106: {"Descr": "<Username> registered Task Scheduler <TaskName>",
          "TaskName": "TaskName",
          "UserContext": "Username"},

    118: {"Descr": "Task Scheduler launched <TaskInstanceId> of <TaskName> due to system startup",
          "TaskName": "TaskName",
          "InstanceId": "TaskInstanceId"},

    119: {"Descr": "Task Scheduler launched <TaskInstanceId of <TaskName> due to <Username> logon",
          "TaskName": "TaskName",
          "UserName": "Username",
          "InstanceId": "TaskInstanceId"},

    140: {"Descr": "<Username> updated Task Scheduler <TaskName>",
          "TaskName": "TaskName",
          "UserName": "Username"},

    141: {"Descr": "<Username> deleted Task Scheduler <TaskName>",
          "TaskName": "TaskName",
          "UserName": "Username"},

    200: {"Descr": "Task Scheduler launched <ApplicationPath> in <TaskInstanceId> of <TaskName>",
          "TaskName": "TaskName",
          "ActionName": "ApplicationPath",
          "TaskInstanceId": "TaskInstanceId"},

    201: {"Descr": "Task Scheduler successfully completed <TaskName>, <TaskInstanceId>, <ApplicationPath>",
          "TaskName": "TaskName",
          "ActionName": "ApplicationPath",
          "TaskInstanceId": "TaskInstanceId",
          "ResultCode": "ResultCode"},
}

shell = {  # Microsoft-Windows-Shell-Core/Operational
    9707: {"Descr": "Started execution of <Command>",  # from Run/RunOnce?
           "Command": "Command"},

    9708: {"Descr": "Finished execution of <Command> (PID <ProcessPid>)",  # from Run/RunOnce
           "Command": "Command",
           "PID": "ProcessId"}
}

smbclient = {  # Microsoft-Windows-SmbClient/Security
    31001: {"Descr": "Failed logon to <ServerName>",
            "Reason": "Reason",
            "Status": "Status",
            "SecurityStatus": "SecurityStatus",
            "TargetLogonId": "TargetLogonId",
            "UserName": "TargetUsername",
            "ServerName": "ServerName",  # TODO - change to TargetHost?
            "PrincipalName": "PrincipalName"},  # TODO - change to SPN?

    31010: {"Descr": "The SMB client failed to connect to the share.",
            "Reason": "Reason",
            "Status": "Status",
            "ShareName": "ShareName",
            "ObjectName": "ObjectName"}
}

smbserver1 = {  # Microsoft-Windows-SMBServer/Analytic
    # Provider: Microsoft-Windows-SMBServer
    551: {"Descr": "Smb Session Authentication Failure",
          "SessionGUID": "SessionGuid",
          "ConnectionGUID": "ConnectionGuid",
          "Status": "Status"},

    # Provider: Microsoft-Windows-SMBServer
    552: {"Descr": "SMB2 Session Authentication Success",
          "SessionGUID": "SessionGuid",
          "ConnectionGUID": "ConnectionGuid",
          "UserName": "TargetUsername",
          "DomainName": "TargetDomain"},

    # Provider: Microsoft-Windows-SMBServer
    553: {"Descr": "SMB2 Session Bound to Connection",
          "SessionGUID": "SessionGuid",
          "ConnectionGUID": "ConnectionGuid",
          "BindingSessionGUID": "BindingSessionGuid"},

    # Provider: Microsoft-Windows-SMBServer
    554: {"Descr": "Session Terminated",
          "SessionGUID": "SessionGuid",
          "Reason": "Reason"},

    # Provider: Microsoft-Windows-SMBServer
    600: {"Descr": "SMB2 TreeConnect Allocated",
          "TreeConnectGUID": "TreeConnectGuid",
          "SessionGUID": "SessionGuid",
          "ConnectionGUID": "ConnectionGuid",
          "ShareGUID": "ShareGuid",
          "ShareName": "ShareName",
          "ScopeName": "ScopeName",
          "ShareProperties": "ShareProperties"},

    # Provider: Microsoft-Windows-SMBServer
    601: {"Descr": "SMB2 TreeConnect Disconnected",
          "TreeConnectGUID": "TreeConnectGuid",
          "SessionGUID": "SessionGuid",
          "ConnectionGUID": "ConnectionGuid"},

    # Provider: Microsoft-Windows-SMBServer
    602: {"Descr": "SMB2 TreeConnect Terminated",
          "TreeConnectGUID": "TreeConnectGuid",
          "SessionGUID": "SessionGuid"},

    # Provider: Microsoft-Windows-SMBServer
    700: {"Descr": "SMB2 Share Added",
          "ShareName": "ShareName",
          "ServerName": "ServerName",
          "PathName": "PathName",
          "CSCState": "CSCState",
          "ClusterShareType": "ClusterShareType",
          "ShareProperties": "ShareProperties",
          "CaTimeOut": "CaTimeOut",
          "ShareState": "ShareState"},

    # Provider: Microsoft-Windows-SMBServer
    701: {"Descr": "SMB2 Share Modified",
          "ShareName": "ShareName",
          "ServerName": "ServerName",
          "PathName": "PathName",
          "CSCState": "CSCState",
          "ClusterShareType": "ClusterShareType",
          "ShareProperties": "ShareProperties",
          "CaTimeOut": "CaTimeOut",
          "ShareState": "ShareState"},

    # Provider: Microsoft-Windows-SMBServer
    702: {"Descr": "SMB2 Share Deleted",
          "ShareName": "ShareName",
          "ServerName": "ServerName"}
}

smbserver2 = {  # Microsoft-Windows-SMBServer/Audit
    # Provider: Microsoft-Windows-SMBServer
    3000: {"Descr": "SMB1 access",
           "ClientName": "ClientName"}
}

smbserver3 = {  # Microsoft-Windows-SMBServer/Connectivity
    # Provider: Microsoft-Windows-SMBServer
    1022: {"Descr": "File and printer sharing firewall rule enabled"}
}

smbserver4 = {  # Microsoft-Windows-SMBServer/Operational
    # Provider: Microsoft-Windows-SMBServer
    1023: {"Descr": "One or more shares present on this server have access based enumeration enabled"},

    # Provider: Microsoft-Windows-SMBServer
    1024: {"Descr": "SMB2 and SMB3 have been disabled on this server"},

    # Provider: Microsoft-Windows-SMBServer
    1025: {"Descr": "One or more named pipes or shares have been marked for access by anonymous users"}
}

smbserver5 = {  # Microsoft-Windows-SMBServer/Security
    # Provider: Microsoft-Windows-SMBServer
    551: {"Descr": "SMB session authentication failure",
          "SessionGUID": "SessionGuid",
          "ConnectionGUID": "ConnectionGuid",
          "Status": "Status",
          "TranslatedStatus": "TranslatedStatus",
          "ClientAddress": "ClientAddress",
          "SessionId": "SessionId",
          "UserName": "Username",
          "ClientName": "ClientName"},

    # Provider: Microsoft-Windows-SMBServer
    1006: {"Descr": "The share denied access to the client",
           "ShareName": "ShareName",
           "SharePath": "SharePath",
           "ClientAddress": "ClientAddress",
           "UserName": "Username",
           "ClientName": "ClientName",
           "MappedAccess": "MappedAccess",
           "GrantedAccess": "GrantedAccess",
           "ShareSecurityDescriptor": "ShareSecurityDescriptor",
           "Status": "Status",
           "TranslatedStatus": "TranslatedStatus",
           "SessionID": "SessionID"},

    # Provider: Microsoft-Windows-SMBServer
    1007: {"Descr": "The share denied anonymous access to the client",
           "ShareName": "ShareName",
           "SharePath": "SharePath",
           "ClientAddress": "ClientAddress",
           "ClientName": "ClientName"},

    # Provider: Microsoft-Windows-SMBServer
    1009: {"Descr": "The share denied anonymous access to the client",
           "ClientAddress": "ClientAddress",
           "ClientName": "ClientName",
           "SessionId": "SessionId",
           "SessionGUID": "SessionGuid",
           "ConnectionGUID": "ConnectionGuid"},

    # Provider: Microsoft-Windows-SMBServer
    1021: {"Descr": "LmCompatibilityLevel value is different from the default",
           "ConfiguredLmCompatibilityLevel": "+ConfiguredLmCompatibilityLevel",
           "DefaultLmCompatibilityLevel": "+DefaultLmCompatibilityLevel"}
}

storsvc = {  # Microsoft-Windows-Storsvc/Diagnostic
    # Provider: Microsoft-Windows-Storsvc
    1001: {"Descr": "NIL",
           "Version": "Version",
           "DiskNumber": "DiskNumber",
           "VendorId": "Vendor",
           "ProductRevision": "ProductRevision",
           "SerialNumber": "SerialNumber",
           "ParentId": "ParentId",
           "FileSystem": "FileSystem",
           "BusType": "+BusType",
           "PartitionStyle": "+PartitionStyle",
           "VolumeCount": "VolumeCount",
           "ContainsRawVolumes": "ContainsRawVolumes",
           "Size": "Capacity"},

    # Provider: Microsoft-Windows-Storsvc
    1002: {"Descr": "NIL",
           "Version": "Version",
           "Epoch": "Epoch",
           "DiskIndex": "DiskIndex",
           "TotalDisks": "TotalDisks",
           "DiskNumber": "DiskNumber",
           "VendorId": "Vendor",
           "ProductId": "Product",
           "ProductRevision": "ProductRevision",
           "SerialNumber": "SerialNumber",
           "ParentId": "ParentId",
           "FileSystem": "FileSystem",
           "BusType": "+BusType",
           "PartitionStyle": "+PartitionStyle",
           "VolumeCount": "VolumeCount",
           "ContainsRawVolumes": "ContainsRawVolumes",
           "Size": "Capacity"}
}

symantec = {  # Symantec Endpoint Protection Client
    51: {"Descr": "Detection Finish"}  # TODO
}

wdef = {  # Microsoft-Windows-Windows Defender/Operational
    1006: {"Descr": "<ProductName> has detected malware or other potentially unwanted software",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Detection Source": "Source",
           "Process Name": "ProcessPath",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatId",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path Found": "Path",
           "Detection Origin": "Origin",
           "Execution Status": "ExecutionStatus",
           "Detection Type": "Type",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1007: {"Descr": "<ProductName> has taken action to protect this machine from malware or "
                    "other potentially unwanted software",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Status Description": "Status",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatId",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Cleaning Action": "Cleaning Action",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1008: {"Descr": "<ProductName> has encountered an error when taking action on malware or "
                    "other potentially unwanted software",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Status Description": "Status",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatId",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1009: {"Descr": "<ProductName> has restored an item from quarantine",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatId",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1010: {"Descr": "<ProductName> has encountered an error trying to restore an item from quarantine",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatId",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1011: {"Descr": "<ProductName> has deleted an item from quarantine",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatId",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1012: {"Descr": "<ProductName> has encountered an error trying to restore an item from quarantine",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatId",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1015: {"Descr": "<ProductName> has detected a suspicious behavior",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Detection Source": "Source",
           "Process Name": "ProcessPath",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatId",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path Found": "Path",
           "Detection Origin": "Origin",
           "Execution Status": "ExecutionStatus",
           "Detection Type": "Type",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion",
           "Process ID": "ProcessId",
           "Signature ID": "SignatureId",
           "FidelityValue": "FidelityValue",
           "FidelityLabel": "FidelityLabel",
           "Image File Hash": "ImageFileHash",
           "TargetFileName": "TargetFileName",
           "TargetFileHash": "TargetFileHash"},

    1116: {"Descr": "<ProductName> has detected malware or other potentially unwanted software",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Detection Time": "DetectionTime",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Status Description": "Status",
           "Source Name": "Source",
           "Process Name": "ProcessPath",
           "Detection User": "DetectionUser",
           "Path": "Path",
           "Origin Name": "Origin",
           "Execution Name": "Execution",
           "Type Name": "Type",
           "Action Name": "Action",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Post Clean Status": "PostCleanStatus",
           "Additional Actions String": "AdditionalActions",
           "Remediation User": "RemediationUser",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1117: {"Descr": "<ProductName> has taken action to protect this machine from malware or "
                    "other potentially unwanted software",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Detection Time": "DetectionTime",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Status Description": "Status",
           "Source Name": "Source",
           "Process Name": "ProcessPath",
           "Detection User": "DetectionUser",
           "Path": "Path",
           "Origin Name": "Origin",
           "Execution Name": "Execution",
           "Type Name": "Type",
           "Action Name": "Action",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Post Clean Status": "PostCleanStatus",
           "Additional Actions String": "AdditionalActions",
           "Remediation User": "RemediationUser",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1118: {"Descr": "<ProductName> has encountered a non-critical error when taking action on malware or "
                    "other potentially unwanted software",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Detection Time": "DetectionTime",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Status Description": "Status",
           "Source Name": "Source",
           "Process Name": "ProcessPath",
           "Detection User": "DetectionUser",
           "Path": "Path",
           "Origin Name": "Origin",
           "Execution Name": "Execution",
           "Type Name": "Type",
           "Action Name": "Action",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Post Clean Status": "PostCleanStatus",
           "Additional Actions String": "AdditionalActions",
           "Remediation User": "RemediationUser",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1119: {"Descr": "<ProductName> has encountered a critical error when taking action on malware or "
                    "other potentially unwanted software",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Detection Time": "DetectionTime",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Status Description": "Status",
           "Source Name": "Source",
           "Process Name": "ProcessPath",
           "Detection User": "DetectionUser",
           "Path": "Path",
           "Origin Name": "Origin",
           "Execution Name": "Execution",
           "Type Name": "Type",
           "Action Name": "Action",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Post Clean Status": "PostCleanStatus",
           "Additional Actions String": "AdditionalActions",
           "Remediation User": "RemediationUser",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    1160: {"Descr": "<ProductName has detected potentially unwanted application (PUA)",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionId",
           "Detection Time": "DetectionTime",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Status Description": "Status",
           "Source Name": "Source",
           "Process Name": "ProcessPath",
           "Detection User": "DetectionUser",
           "Path": "Path",
           "Origin Name": "Origin",
           "Execution Name": "Execution",
           "Type Name": "Type",
           "Action Name": "Action",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Post Clean Status": "PostCleanStatus",
           "Additional Actions String": "AdditionalActions",
           "Remediation User": "RemediationUser",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    2050: {"Descr": "<ProductName> has uploaded a file for further analysis",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Filename": "FileName",
           "Sha256": "FileHash"},

    2051: {"Descr": "<ProductName> has encountered an error trying to upload a suspicious file for further analysis",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Filename": "FileName",
           "Sha256": "FileHash",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion",
           "Error Code": "ErrorCode"},

    5000: {"Descr": "<ProductName> Real-time Protection scanning for malware and "
                    "other potentially unwanted software was enabled",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    5001: {"Descr": "<ProductName> Real-time Protection scanning for malware and "
                    "other potentially unwanted software was disabled",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    5004: {"Descr": "<ProductName> Real-time Protection feature configuration has changed",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Feature Name": "Feature",
           "Feature ID": "FeatureId"},

    5007: {"Descr": "<ProductName> Configuration has changed. "
                    "If this is unexpected, you should review the settings as this may be the result of malware",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Old Value": "OldValue",
           "New Value": "NewValue"},

    5008: {"Descr": "<ProductName> engine has been terminated due to an unexpected error",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Resource": "Resource",
           "Failure Type": "FailureType",
           "Exception Code": "ExceptionCode"},

    5009: {"Descr": "<ProductName> scanning for spyware and other potentially unwanted software has been enabled",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    5010: {"Descr": "<ProductName> scanning for spyware and other potentially unwanted software is disabled",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    5011: {"Descr": "<ProductName> scanning for viruses has been enabled",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    5012: {"Descr": "<ProductName> scanning for viruses is disabled",
           "Product Name": "ProductName",
           "Product Version": "ProductVersion"}
}

winrm = {  # Microsoft-Windows-WinRM/Operational
    6: {"Descr": "Creating WSMan session. The connection string is <Connection>",
        "connection": "Connection"},

    8: {"Descr": "Closing WSMan session"},  # empty

    15: {"Descr": "Closing WSMan command"},  # empty

    16: {"Descr": "Closing WSMan shell"},  # empty

    33: {"Descr": "Closing WSMan session completed successfully"},  # empty

    91: {"Descr": "Creating WSMan shell on server with <ResourceUri>",
         "resourceUri": "ResourceUri",
         "shellId": "ShellId"},

    169: {"Descr": "<TargetUsername> authenticated successfully using <AuthMechanism>",  # Win7 only?
          "username": "TargetUsername",
          "authenticationMechanism": "AuthMechanism"}
}

wlan = {  # Microsoft-Windows-WLAN-AutoConfig/Operational
    # Provider: Microsoft-Windows-WLAN-AutoConfig
    8001: {"Descr": "WLAN AutoConfig service has successfully connected to a wireless network",
           "InterfaceGuid": "InterfaceGuid",
           "InterfaceDescription": "InterfaceDescr",
           "ConnectionMode": "ConnectionMode",
           "ProfileName": "ProfileName",
           "SSID": "SSID",
           "BSSType": "BSSType",
           "PHYType": "PHYType",
           "AuthenticationAlgorithm": "AuthAlgo",
           "CipherAlgorithm": "CipherAlgo",
           "OnexEnabled": "IsOnexEnabled",
           "ConnectionId": "ConnectionId",
           "NonBroadcast": "IsNonBroadcast"},

    # Provider: Microsoft-Windows-WLAN-AutoConfig
    8002: {"Descr": "WLAN AutoConfig service failed to connect to a wireless network",
           "InterfaceGuid": "InterfaceGuid",
           "InterfaceDescription": "InterfaceDescr",
           "ConnectionMode": "ConnectionMode",
           "ProfileName": "ProfileName",
           "SSID": "SSID",
           "BSSType": "BSSType",
           "FailureReason": "FailureReason",
           "ReasonCode": "ReasonCode",
           "ConnectionId": "ConnectionId",
           "RSSI": "RSSI"},

    # Provider: Microsoft-Windows-WLAN-AutoConfig
    8003: {"Descr": "WLAN AutoConfig service has successfully disconnected from a wireless network",
           "InterfaceGuid": "InterfaceGuid",
           "InterfaceDescription": "InterfaceDescr",
           "ConnectionMode": "ConnectionMode",
           "ProfileName": "ProfileName",
           "SSID": "SSID",
           "BSSType": "BSSType",
           "Reason": "Reason",
           "ConnectionId": "ConnectionId",
           "ReasonCode": "ReasonCode"},

    # Provider: Microsoft-Windows-WLAN-AutoConfig
    11000: {"Descr": "Wireless network association started",
            "DeviceGuid": "InterfaceGuid",
            "Adapter": "InterfaceDescr",
            "LocalMac": "LocalMac",
            "SSID": "SSID",
            "BSSType": "BSSType",
            "Auth": "AuthAlgo",
            "Cipher": "CipherAlgo",
            "OnexEnabled": "IsOnexEnabled",
            "ConnectionId": "ConnectionId",
            "IhvConnectivitySetting": "IhvConnectivitySetting"}
}

wmi = {  # Microsoft-Windows-WMI-Activity/Operational (Win8+)
    5857: {"Descr": "<ProviderName> started with <ResultCode>",  # wmiprvse execution
           "ProviderName": "ProviderName",
           "Code": "ResultCode",
           "HostProcess": "ProcessName",
           "ProcessID": "ProcessID",
           "ProviderPath": "ProviderPath"},

    5860: {"Descr": "Registration of temporary event consumer",  # Win10 v1511+
           "NamespaceName": "Namespace",
           "Query": "Query",
           "User": "Username",
           "processid": "ProcessId",  # < Win10 v1803
           "Processid": "ProcessId",  # Win10 v1803+
           "MachineName": "Hostname",  # < Win10 v1803
           "ClientMachine": "Hostname",  # Win10 v1803+
           "PossibleCause": "PossibleCause"},

    5861: {"Descr": "Registration of permanent event consumer",  # Win10 v1607+
           "Namespace": "Namespace",
           "ESS": "ESS",
           "CONSUMER": "Consumer",
           "PossibleCause": "PossibleCause"}
}
