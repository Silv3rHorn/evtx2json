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
           "LogonType": "TargetLogonType",  # to convert
           "WorkstationName": "WorkstationName",
           "IpAddress": "IP",
           "IpPort": "Port",
           "LogonProcessName": "LogonProcessName",
           "Status": "Status",  # to convert
           "FailureReason": "FailureReason",  # %% format
           "SubStatus": "SubStatus",
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

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

    # 4663: An attempt was made to access an object
    4663: {"SubjectUserSid": "SID",
           "SubjectUserName": "Username",
           "SubjectDomainName": "Domain",
           "SubjectLogonId": "LogonId",
           "ObjectType": "ObjectType",
           "ObjectName": "ObjectName",
           "AccessList": "AccessList",  # %% format
           "AccessMask": "AccessMask",  # to convert
           "ProcessId": "ProcessId",
           "ProcessName": "ProcessPath"},

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
           "MemberName": "TargetName",
           "TargetSid": "GroupSID",
           "TargetUserName": "GroupName",
           "TargetDomainName": "GroupDomain"},

    # 4738: A user account was changed  # non-changed values are -, so ignore values that are -?
    4738: {"SubjectUserSid": "SID",
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
           "UserAccountControl": "UserAccountControl"},  # %% format

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
           "AccessList": "AccessList"},

    # 5156: The Windows Filtering Platform has permitted a connection
    5156: {"ProcessId": "ProcessId",
           "Application": "ProcessPath",
           "Direction": "Direction",  # %% format
           "IpAddress": "IP",
           "IpPort": "Port",
           "DestAddress": "TargetIP",
           "DestPort": "TargetPort",
           "Protocol": "Protocol",
           "RemoteUserID": "TargetSID",
           "RemoteMachineID": "TargetMachineSID"},
}

sys = {  # System
    # 104: Clearing of event log
    104: {"SubjectUserName": "Username",
          "SubjectDomainName": "Domain",
          "Channel": "EventLogName",
          "BackupPath": "BackupPath"},

    # 1001: Windows Error Reporting
    1001: {},  # TODO

    # 7040: The start type of a service was changed
    7040: {"param1": "ServiceName",
           "param2": "StatusBefore",
           "param3": "StatusAfter"},

    # 7045: A service was installed on the system
    7045: {"ServiceName": "ServiceName",
           "ImagePath": "ServicePath",
           "ServiceType": "ServiceType",
           "AccountName": "Username"},

    # 9009: The Desktop Window Manager has exited with code <x>
    9009: {
        "Param1": "ExitCode"}
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

rcm = {  # Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
    # 1149: An RDP session has been successfully established
    1149: {"Param1": "TargetUsername",
           "Param2": "TargetDomain",
           "Param3": "IP"}
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

    403: {}
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

wdef = {  # Microsoft-Windows-Windows Defender/Operational
    # 1015: The antimalware platform detected suspicious behavior
    1015: {},  # TODO

    # 1116: The antimalware platform detected malware or other potentially unwanted software
    1116: {"Product Name": "ProductName",
           "Product Version": "ProductVersion",
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
           "Error Description": "Error",
           "Post Clean Status": "PostCleanStatus",
           "Additional Actions String": "AdditionalActions",
           "Remediation User": "RemediationUser",
           "Signature Version": "SignatureVersion",
           "Engine Version": "EngineVersion"}
}

symantec = {  # Symantec Endpoint Protection Client
    # 51: Detection Finish
    51: {}
}
