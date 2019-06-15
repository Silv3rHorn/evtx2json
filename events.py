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
           "LogonType": "LogonType",  # to convert
           "WorkstationName": "WorkstationName",
           "LogonGuid": "LogonGUID",
           "TransmittedServices": "TransmittedServices",
           "IpAddress": "IP",
           "IpPort": "Port",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath",
           "RestrictedAdminMode": "RestrictedAdminMode",  # Win 10+
           "ElevatedToken": "ElevatedToken"},  # Win 10+

    4625: {"Descr": "An account failed to log on",
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "LogonType": "LogonType",  # to convert
           "WorkstationName": "WorkstationName",
           "IpAddress": "IP",
           "IpPort": "Port",
           "LogonProcessName": "LogonProcessName",
           "Status": "Status",  # to convert
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
           "LogonType": "LogonType",
           "GroupMembership": "GroupMembership"},  # to convert

    4634: {"Descr": "An account was logged off",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonId": "TargetLogonId",
           "LogonType": "LogonType"},  # to convert

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
           "SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
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
           "MandatoryLabel": "MandatoryLabel",  # to convert
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
           "ServiceType": "ServiceType",  # to convert
           "ServiceStartType": "ServiceStartType",  # to convert
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
           "UserAccountControl": "UserAccountControl"},  # to convert (%% joined with ' ')

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
           "OldUacValue": "OldUacValue",
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
           "TicketOptions": "TicketOptions",  # to convert, bitflag
           "Status": "ResultCode",  # to convert
           "TicketEncryptionType": "TicketEncryptionType",  # to convert
           "PreAuthType": "PreAuthType",  # to convert
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
           "TicketOptions": "TicketOptions",  # to convert
           "Status": "ResultCode",  # to convert
           "TicketEncryptionType": "TicketEncryptionType",  # to convert
           "PreAuthType": "PreAuthType",  # to convert
           "IpAddress": "IP",
           "IpPort": "Port",
           "LogonGuid": "LogonGUID",
           "TransmittedServices": "TransmittedServices"},

    4771: {"Descr": "Kerberos pre-authentication failed",
           "TargetUserName": "TargetUsername",
           "TargetSid": "TargetSID",
           "ServiceName": "ServiceName",
           "TicketOptions": "TicketOptions",  # to convert
           "Status": "ResultCode",  # to convert
           "PreAuthType": "PreAuthType",  # to convert
           "IpAddress": "IP",
           "IpPort": "Port"},

    4776: {"Descr": "The computer attempted to validate the credentials for an account",
           "TargetUserName": "TargetUsername",
           "Workstation": "WorkstationName",
           "Status": "ResultCode"},  # to convert

    4778: {"Descr": "A session was reconnected to a Window Station",
           "AccountName": "TargetUsername",
           "AccountDomain": "TargetDomain",
           "LogonID": "TargetLogonId",
           "SessionName": "SessionName",
           "ClientName": "WorkstationName",
           "ClientAddress": "IP"},

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
           "Protocol": "Protocol"},  # to convert

    5156: {"Descr": "The Windows Filtering Platform has permitted a connection",
           "ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "IpAddress": "IP",
           "IpPort": "Port",
           "DestAddress": "TargetIP",
           "DestPort": "TargetPort",
           "Protocol": "Protocol",  # to convert
           "RemoteUserID": "TargetSID",
           "RemoteMachineID": "TargetMachineSID"},

    5158: {"Descr": "The Windows Filtering Platform has permitted a bind to a local port",
           "ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "SourceAddress": "IP",
           "SourcePort": "Port",
           "Protocol": "Protocol"}  # to convert
}

sys = {  # System
    104: {"Descr": "The <EventLogName> log file was cleared",
          "SubjectUserName": "Username",
          "SubjectDomainName": "Domain",
          "Channel": "EventLogName",
          "BackupPath": "BackupPath"},

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
           "Param1": "ExitCode"}
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

dns = {  # Microsoft-Windows-DNSServer/Analytical (Windows Server 2016+)
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

fwall = {  # Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
    2004: {"Descr": "A rule has been added to the Windows Firewall exception list",
           "RuleId": "RuleId",
           "RuleName": "RuleName",
           "Origin": "Origin",  # to convert
           "ApplicationPath": "ApplicationPath",
           "ServiceName": "ServiceName",
           "Direction": "Direction",  # to convert
           "Protocol": "Protocol",  # to convert
           "LocalPorts": "TargetPort",
           "RemotePorts": "RemotePorts",
           "Action": "Action",  # to convert
           "Profiles": "Profiles",  # to convert
           "LocalAddresses": "TargetIP",
           "EmbeddedContext": "EmbeddedContext",
           "Active": "Active",  # to convert
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"},

    2005: {"Descr": "A rule has been modified in the Windows Firewall exception list",
           "RuleId": "RuleId",
           "RuleName": "RuleName",
           "Origin": "Origin",  # to convert
           "ApplicationPath": "ApplicationPath",
           "ServiceName": "ServiceName",
           "Direction": "Direction",  # to convert
           "Protocol": "Protocol",  # to convert
           "LocalPorts": "TargetPort",
           "RemotePorts": "RemotePorts",
           "Action": "Action",  # to convert
           "Profiles": "Profiles",  # to convert
           "LocalAddresses": "TargetIP",
           "EmbeddedContext": "EmbeddedContext",
           "Active": "Active",  # to convert
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"},

    2006: {"Descr": "A rule has been deleted in the Windows Firewall exception list",
           "RuleId": "RuleId",
           "RuleName": "RuleName",
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"}
}

offlinef = {  # Microsoft-Windows-OfflineFiles/Operational
    7: {"Descr": "User logon detected: <Username> <Session>",
        "Account": "TargetUsername",
        "Session": "TargetSessionId"},

    8: {"Descr": "User logoff detected: <Username> <Session>",
        "Account": "TargetUsername",
        "Session": "TargetSessionId"}
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
         "Reason": "Reason"},  # to convert

    41: {"Descr": "Begin session arbitration",  # Win8.1+
         "User": "TargetUsername",
         "SessionID": "TargetSessionId"}
}

pshell1 = {  # Windows PowerShell
    400: {"Descr": "Engine state is changed from <PreviousEngineState> to <NewEngineState>"},  # start of session

    403: {"Descr": "Engine state is changed from <PreviousEngineState> to <NewEngineState>"},  # end of session

    500: {"Descr": "Command <CommandName> is <NewCommandState>"},  # start of execution

    501: {"Descr": "Command <CommandName> is <NewCommandState>"},  # end of execution

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
            "param1": "ProcessPath",
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
          "ClientIP": "IPPort"}
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

    200: {"Descr": "Task Scheduler launched <ActionName> in <TaskInstanceId of <TaskName>",
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
            "PrincipalName": "PrincipalName"}  # TODO - change to SPN?
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
           "processid": "ProcessId",
           "MachineName": "Hostname",
           "PossibleCause": "PossibleCause"},

    5861: {"Descr": "Registration of permanent event consumer",  # Win10 v1607+
           "Namespace": "Namespace",
           "ESS": "ESS",
           "CONSUMER": "Consumer",
           "PossibleCause": "PossibleCause"}
}
