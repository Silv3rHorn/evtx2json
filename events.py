sec = {  # Security
    # 1102: The audit log was cleared
    1102: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId"},

    # 4616: The system time was changed
    4616: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "PreviousTime": "PreviousTime",
           "NewTime": "NewTime",
           "ProcessId": "ProcessId",  # Win 7+
           "ProcessName": "ProcessPath"},  # Win 7+

    # 4624: An account was successfully logged on
    4624: {"SubjectUserSid": "SID",
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

    # 4625: An account failed to log on
    4625: {"SubjectUserSid": "SID",
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

    # 4627: Group membership information
    4627: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "LogonType": "LogonType",
           "GroupMembership": "GroupMembership"},  # to convert

    # 4634: An account was logged off
    4634: {"TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonId": "TargetLogonId",
           "LogonType": "LogonType"},  # to convert

    # 4647: User initiated logoff
    4647: {"TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonId": "TargetLogonId"},

    # 4648: A logon was attempted using explicit credentials
    4648: {"SubjectUserSid": "SID",
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

    # 4657: A registry value was modified
    4657: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectName": "RegKey",
           "ObjectValueName": "RegValue",
           "OperationType": "ModType",
           "OldValueType": "OldValueType",
           "OldValue": "OldValue",
           "NewValueType": "NewValueType",
           "NewValue": "NewValue",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

    # 4661: A handle to an object was requested
    4661: {"SubjectUserSid": "SID",
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

    # 4662: An operation was performed on an object
    4662: {"SubjectUserSid": "SID",
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

    # 4663: An attempt was made to access an object
    4663: {"SubjectUserSid": "SID",
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

    # 4672: Special privileges assigned to new logon
    4672: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "PrivilegeList": "PrivilegeList"},

    # 4673: A privileged service was called
    4673: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectServer": "ObjectServer",
           "Service": "Service",
           "PrivilegeList": "PrivilegeList",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

    # 4688: A new process has been created
    4688: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "NewProcessId": "NewProcessId",
           "NewProcessName": "NewProcessPath",
           "TokenElevationType": "TokenElevationType",  # %% format
           "CommandLine": "CommandLine",  # Win 8.1+
           "ProcessId": "ProcessId",
           # Win 10+
           "ParentProcessName": "ProcessPath",
           "MandatoryLabel": "MandatoryLabel",  # to convert
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetLogonId": "TargetLogonId"},

    # 4697: A service was installed in the system
    4697: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ServiceName": "ServiceName",
           "ServiceFileName": "ServicePath",
           "ServiceType": "ServiceType",  # to convert
           "ServiceStartType": "ServiceStartType",  # to convert
           "ServiceAccount": "Username"},

    # 4698: A scheduled task was created
    4698: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContent": "TaskContent"},

    # 4699: A scheduled task was deleted
    4699: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContent": "TaskContent"},

    # 4700: A scheduled task was enabled
    4700: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContent": "TaskContent"},

    # 4701: A scheduled task was disabled
    4701: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContent": "TaskContent"},

    # 4702: A scheduled task was updated
    4702: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TaskName": "TaskName",
           "TaskContentNew": "TaskContent"},

    # 4719: System audit policy was changed
    4719: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "CategoryId": "CategoryId",  # %% format
           "SubcategoryId": "SubcategoryId",  # %% format
           "SubcategoryGuid": "SubcategoryGuid",  # %% format
           "AuditPolicyChanges": "AuditPolicyChanges"},  # %% format (multiple, joined with ', ')

    # 4720: A user account was created
    4720: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "PrivilegeList": "Privilege List",
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

    # 4726: A user account was deleted
    4726: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserSid": "TargetSID",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain"},

    # 4728: A member was added to a security enabled global group
    4728: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "MemberSid": "TargetSID",
           "MemberName": "TargetUsername",
           "TargetSid": "TargetGroupSID",
           "TargetUserName": "TargetGroup",
           "TargetDomainName": "TargetDomain",
           "PrivilegeList": "PrivilegeList"},

    # 4732: A member was added to a security-enabled local group
    4732: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "MemberSid": "TargetSID",
           "MemberName": "TargetUsername",
           "TargetSid": "TargetGroupSID",
           "TargetUserName": "TargetGroup",
           "TargetDomainName": "TargetDomain",
           "PrivilegeList": "PrivilegeList"},

    # 4738: A user account was changed  # non-changed values are -, so ignore values that are -?
    4738: {"SubjectUserSid": "SID",
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

    # 4741: A computer account was created
    4741: {"SubjectUserSid": "SID",
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

    # 4768: A Kerberos authentication ticket (TGT) was requested
    4768: {"TargetUserSid": "TargetSID",
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
           "CertIssuerName": "CertIssuerName",
           "CertSerialNumber": "CertSerialNumber",
           "CertThumbprint": "CertThumbprint"},

    # 4769: A Kerberos service ticket was requested
    4769: {"TargetUserName": "TargetUsername",
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

    # 4771: Kerberos pre-authentication failed
    4771: {"TargetUserName": "TargetUsername",
           "TargetSid": "TargetSID",
           "ServiceName": "ServiceName",
           "TicketOptions": "TicketOptions",  # to convert
           "Status": "ResultCode",  # to convert
           "PreAuthType": "PreAuthType",  # to convert
           "IpAddress": "IP",
           "IpPort": "Port"},

    # 4776: The computer attempted to validate the credentials for an account
    4776: {"TargetUserName": "TargetUsername",
           "Workstation": "WorkstationName",
           "Status": "ResultCode"},  # to convert

    # 4778: A session was reconnected to a Window Station
    4778: {"AccountName": "TargetUsername",
           "AccountDomain": "TargetDomain",
           "LogonID": "TargetLogonId",
           "SessionName": "SessionName",
           "ClientName": "WorkstationName",
           "ClientAddress": "IP"},

    # 4779: A session was disconnected from a Window Station
    4779: {"AccountName": "TargetUsername",
           "AccountDomain": "TargetDomain",
           "LogonID": "TargetLogonId",
           "SessionName": "SessionName",
           "ClientName": "WorkstationName",
           "ClientAddress": "IP"},

    # 4798: A user's local group membership was enumerated
    4798: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetSid": "TargetSID",
           "CallerProcessId": "ProcessId",
           "CallerProcessName": "ProcessPath"},

    # 4799: A security-enabled local group membership was enumerated
    4799: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "TargetUserName": "TargetUsername",
           "TargetDomainName": "TargetDomain",
           "TargetSid": "TargetSID",
           "CallerProcessId": "ProcessId",
           "CallerProcessName": "ProcessPath"},

    # 4825: A user was denied the access to Remote Desktop. By default,
    # users are allowed to connect only if they are members of the Remote Desktop Users group or Administrators group.
    4825: {"AccountName": "TargetUsername",
           "AccountDomain": "TargetDomain",
           "LogonID": "TargetLogonId",
           "ClientAddress": "IP"},

    # 5140: A network share object was accessed
    5140: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectType": "ObjectType",
           "ShareName": "ShareName",
           "ShareLocalPath": "ShareLocalPath",
           "IpAddress": "IP",
           "IpPort": "Port",
           "AccessList": "AccessList"},  # %% format

    # 5142: A network share object was added
    5142: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ShareName": "ShareName",
           "ShareLocalPath": "ShareLocalPath"},

    # 5144: A network share object was deleted
    5144: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ShareName": "ShareName",
           "ShareLocalPath": "ShareLocalPath"},

    # 5145: A network share object was checked to see whether client can be granted desired access
    5145: {"SubjectUserSid": "SID",
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

    # 5152: The Windows Filtering Platform blocked a packet
    5152: {"ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "SourceAddress": "IP",
           "SourcePort": "Port",
           "DestAddress": "TargetIP",
           "DestPort": "TargetPort",
           "Protocol": "Protocol"},  # to convert

    # 5156: The Windows Filtering Platform has permitted a connection
    5156: {"ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "IpAddress": "IP",
           "IpPort": "Port",
           "DestAddress": "TargetIP",
           "DestPort": "TargetPort",
           "Protocol": "Protocol",  # to convert
           "RemoteUserID": "TargetSID",
           "RemoteMachineID": "TargetMachineSID"},

    # 5158: The Windows Filtering Platform has permitted a bind to a local port
    5158: {"ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "SourceAddress": "IP",
           "SourcePort": "Port",
           "Protocol": "Protocol"},  # to convert
}

sys = {  # System
    # 104: Clearing of event log
    104: {"SubjectUserName": "Username",
          "SubjectDomainName": "Domain",
          "Channel": "EventLogName",
          "BackupPath": "BackupPath"},

    # 1001: Windows Error Reporting
    1001: {},  # TODO

    # 7036: The %1 service entered the %2 state
    7036: {"param1": "ServiceName",
           "param2": "StatusAfter"},

    # 7040: The start type of a service was changed
    7040: {"param1": "ServiceName",
           "param2": "StatusBefore",
           "param3": "StatusAfter"},

    # 7045: A service was installed on the system
    7045: {"ServiceName": "ServiceName",
           "ImagePath": "ServicePath",
           "ServiceType": "ServiceType",
           "StartType": "StartType",
           "AccountName": "Username"},

    # 9009: The Desktop Window Manager has exited with code <x>
    9009: {"Param1": "ExitCode"}
}

bits = {  # Microsoft-Windows-Bits-Client/Operational
    # 59: BITS started the transfer job
    59: {"transferId": "TransferId",
         "name": "Name",
         "Id": "JobId",
         "url": "URL",
         "peer": "Peer",
         "fileTime": "FileTime",
         "fileLength": "FileSize"},

    # 60: BITS stopped transferring
    60: {"transferId": "TransferId",
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

fwall = {  # Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
    # 2004: A rule has been added to the Windows Firewall exception list
    2004: {"RuleId": "RuleId",
           "RuleName": "RuleName",
           "Origin": "Origin",  # to convert
           "ApplicationPath": "ApplicationPath",
           "ServiceName": "ServiceName",
           "Direction": "Direction",  # to convert
           "Protocol": "Protocol",  # to convert
           "LocalPorts": "TargetPort",
           "RemotePorts": "RemotePort",
           "Action": "Action",  # to convert
           "Profiles": "Profiles",  # to convert
           "LocalAddresses": "TargetIP",
           "EmbeddedContext": "EmbeddedContext",
           "Active": "Active",  # to convert
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"},

    # 2005: A rule has been modified in the Windows Firewall exception list
    2005: {"RuleId": "RuleId",
           "RuleName": "RuleName",
           "Origin": "Origin",  # to convert
           "ApplicationPath": "ApplicationPath",
           "ServiceName": "ServiceName",
           "Direction": "Direction",  # to convert
           "Protocol": "Protocol",  # to convert
           "LocalPorts": "TargetPort",
           "RemotePorts": "RemotePort",
           "Action": "Action",  # to convert
           "Profiles": "Profiles",  # to convert
           "LocalAddresses": "TargetIP",
           "EmbeddedContext": "EmbeddedContext",
           "Active": "Active",  # to convert
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"},

    # 2006: A rule has been deleted in the Windows Firewall exception list
    2006: {"RuleId": "RuleId",
           "RuleName": "RuleName",
           "ModifyingUser": "SID",
           "ModifyingApplication": "ProcessPath"},
}

lsm = {  # Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    # 21: Remote Desktop Services: Session logon succeeded
    21: {"User": "TargetUsername",
         "SessionID": "TargetSessionId",
         "Address": "IP"},

    # 22: Remote Desktop Services: Shell start notification received
    22: {"User": "TargetUsername",
         "SessionID": "TargetSessionId",
         "Address": "IP"},

    # 23: Remote Desktop Services: Session logoff succeeded
    23: {"User": "TargetUsername",
         "SessionID": "TargetSessionId"},

    # 24: Remote Desktop Services: Session has been disconnected
    24: {"User": "TargetUsername",
         "SessionID": "TargetSessionId",
         "Address": "IP"},

    # 24: Remote Desktop Services: Session reconnection succeeded
    25: {"User": "TargetUsername",
         "SessionID": "TargetSessionId",
         "Address": "IP"},

    # 39: Session <X> has been disconnected by session <Y>
    39: {"TargetSession": "TargetSessionId",
         "Source": "SessionId"},

    # 40: Session <X> has been disconnected, reason code <Z>
    40: {"Session": "TargetSessionId",
         "Reason": "Reason"},  # to convert

    # 41: Begin session arbitration (Win10+ ?)
    41: {"User": "TargetUsername",
         "SessionID": "TargetSessionId"}
}

pshell = {  # Windows PowerShell
    400: {},

    403: {},

    600: {}
}

pshello = {  # Microsoft-Windows-PowerShell/Operational
    # 4103: Module logging
    4103: {"MessageNumber": "MessageNumber",
           "MessageTotal": "MessageTotal",
           "ScriptBlockText": "ScriptBlockText",
           "ScriptBlockId": "ScriptBlockId",
           "Path": "Path"},

    # 4104: Scriptblock module loading
    4104: {"MessageNumber": "MessageNumber",
           "MessageTotal": "MessageTotal",
           "ScriptBlockText": "ScriptBlockText",
           "ScriptBlockId": "ScriptBlockId",
           "Path": "Path"},

    # Status of session
    8197: {"param1": "Status"}
}

rcm = {  # Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
    # 1149: An RDP session has been successfully established
    1149: {"Param1": "TargetUsername",
           "Param2": "TargetDomain",
           "Param3": "IP"}
}

rdpclient = {  # Microsoft-Windows-TerminalServices-RDPClient/Operational
    # 1024: RDP ClientActiveX is trying to connect to the server (<X>)
    1024: {"Value": "TargetHostname"},

    # 1026: RDP ClientActiveX has been disconnected (Reason= <X>)
    1026: {"Value": "Reason"},

    # 1027: Connected to domain (<X>) with session <Y>
    1027: {"DomainName": "TargetDomain",
           "SessionID": "TargetSessionId"},

    # 1029: Base64(SHA256(UserName)) is = <X>
    1029: {"TraceMessage": "TargetUsername"},

    # Destination IP
    1102: {"Value": "TargetIP"}
}

rdpcorets = {  # Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
    # 131: The server accepted a new <X> connection from client <Y>
    131: {"ConnType": "Protocol",
          "ClientIP": "IPPort"},

    # 98: A TCP connection has been successfully established
    98: {}
}

sch = {  # Microsoft-Windows-TaskScheduler/Operational
    # 106: A new job was scheduled
    106: {"TaskName": "TaskName",
          "UserContext": "Username"},

    # 118: Task triggered by computer startup
    118: {"TaskName": "TaskName",
          "InstanceId": "TaskInstanceId"},

    # 119: Task triggered on logon
    119: {"TaskName": "TaskName",
          "UserName": "Username",
          "InstanceId": "TaskInstanceId"},

    # 140: Scheduled task updated
    140: {"TaskName": "TaskName",
          "UserName": "Username"},

    # 141: Scheduled task deleted
    141: {"TaskName": "TaskName",
          "UserName": "Username"},

    # 200: Scheduled task started
    200: {"TaskName": "TaskName",
          "ActionName": "ApplicationPath",
          "TaskInstanceId": "TaskInstanceId"},

    # 201: Scheduled task completed
    201: {"TaskName": "TaskName",
          "ActionName": "ApplicationPath",
          "TaskInstanceId": "TaskInstanceId",
          "ResultCode": "ResultCode"},
}

symantec = {  # Symantec Endpoint Protection Client
    # 51: Detection Finish
    51: {}
}

wdef = {  # Microsoft-Windows-Windows Defender/Operational
    # 1006: <ProductName> has detected malware or other potentially unwanted software
    1006: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
           "Detection Source": "Source",
           "Process Name": "ProcessPath",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatID",
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

    # 1007: <ProductName> has taken action to protect this machine from malware or other potentially unwanted software
    1007: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
           "Status Description": "Status",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatID",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Cleaning Action": "Cleaning Action",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    # 1008: <ProductName> has encountered an error when taking action on malware or other potentially unwanted software
    1008: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
           "Status Description": "Status",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatID",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    # 1009: <ProductName> has restored an item from quarantine
    1009: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatID",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    # 1010: <ProductName> has encountered an error trying to restore an item from quarantine
    1010: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatID",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    # 1011: <ProductName> has deleted an item from quarantine
    1011: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatID",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    # 1012: <ProductName> has encountered an error trying to restore an item from quarantine
    1012: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Error Code": "ErrorCode",
           "Error Description": "Error",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatID",
           "Threat Name": "Threat",
           "Severity Name": "Severity",
           "Category Name": "Category",
           "FWLink": "Link",
           "Path": "Path",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"},

    # 1015: <ProductName> has detected a suspicious behavior
    1015: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
           "Detection Source": "Source",
           "Process Name": "ProcessPath",
           "Domain": "Domain",
           "User": "Username",
           "SID": "SID",
           "Threat ID": "ThreatID",
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
           "Process ID": "ProcessID",
           "Signature ID": "Signature ID",
           "FidelityValue": "FidelityValue",
           "FidelityLabel": "FidelityLabel",
           "Image File Hash": "ImageFileHash",
           "TargetFileName": "TargetFileName",
           "TargetFileHash": "TargetFileHash"},

    # 1116: <ProductName> has detected malware or other potentially unwanted software
    1116: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
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

    # 1117: <ProductName> has taken action to protect this machine from malware or other potentially unwanted software
    1117: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
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

    # 1118: <ProductName> has encountered a non-critical error when taking action on malware or
    # other potentially unwanted software
    1118: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
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

    # 1119: <ProductName> has encountered a critical error when taking action on malware or
    # other potentially unwanted software
    1119: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
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

    # 1160: <ProductName has detected potentially unwanted application (PUA)
    1160: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Detection ID": "DetectionID",
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

    # 2050: <ProductName> has uploaded a file for further analysis
    2050: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Filename": "FileName",
           "Sha256": "SHA256"},

    # 2051: <ProductName> has encountered an error trying to upload a suspicious file for further analysis
    2051: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Filename": "FileName",
           "Sha256": "SHA256",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion",
           "Error Code": "ErrorCode"},

    # 5000: <ProductName> Real-time Protection scanning for malware and other potentially unwanted software was enabled
    5000: {"Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    # 5001: <ProductName> Real-time Protection scanning for malware and other potentially unwanted software was disabled
    5001: {"Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    # 5004: <ProductName> Real-time Protection feature configuration has changed
    5004: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Feature Name": "FeatureName",
           "Feature ID": "FeatureID"},

    # 5007: <ProductName> Configuration has changed.
    # If this is an unexpected event you should review the settings as this may be the result of malware
    5007: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Old Value": "OldValue",
           "New Value": "NewValue"},

    # 5008: <ProductName> engine has been terminated due to an unexpected error
    5008: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
           "Resource": "Resource",
           "Failure Type": "FailureType",
           "Exception Code": "ExceptionCode"},

    # 5009: <ProductName> scanning for spyware and other potentially unwanted software has been enabled
    5009: {"Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    # 5010: <ProductName> scanning for spyware and other potentially unwanted software is disabled
    5010: {"Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    # 5011: <ProductName> scanning for viruses has been enabled
    5011: {"Product Name": "ProductName",
           "Product Version": "ProductVersion"},

    # 5012: <ProductName> scanning for viruses is disabled
    5012: {"Product Name": "ProductName",
           "Product Version": "ProductVersion"},
}

winrm = {  # Microsoft-Windows-WinRM/Operational
    # 6: Creating WSMan session
    6: {"connection": "Connection"},

    # 8: Closing WSMan session
    8: {},

    # 33: Closed WSMan session successfully
    33: {},

    # 169: User <X> authenticated successfully using <Y> authentication (not present in Win 10?)
    169: {"username": "TargetUsername",
          "authenticationMechanism": "authenticationMechanism"}
}

wmi = {  # Microsoft-Windows-WMI-Activity/Operational
    # 5857: wmiprvse execution
    5857: {"ProviderName": "ProviderName",
           "Code": "ResultCode",
           "HostProcess": "ProcessName",
           "ProcessID": "ProcessID",
           "ProviderPath": "ProviderPath"},

    # Registration of temporary event consumer
    5860: {"NamespaceName": "Namespace",
           "Query": "Query",
           "User": "Username",
           "Processid": "ProcessId",
           "ClientMachine": "Hostname",
           "PossibleCause": "PossibleCause"},

    # Registration of permanent event consumer
    5861: {"Namespace": "Namespace",
           "ESS": "ESS",
           "CONSUMER": "Consumer",
           "PossibleCause": "PossibleCause"}
}
