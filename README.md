# evtx2json
![](https://img.shields.io/badge/python-3.7-blue.svg)

evtx2json extracts **supported events** from event logs, **standardizes** the fields across events, **dedups** them, 
and exports them to json.

Also includes event description for each exported event.

## Why was this created?
To extract only events and fields **of interest** from multiple event logs, in
a format that is compatible for ingesting and querying with Splunk (or any other Data Analytics platform).

Data Analytics platform is preferred over Excel or Event Log Viewers as it provides querying functions that facilitate 
the aggregation of similar data and reduces the volume of data to be analysed.  

## Dependencies
None if using [**release executable**](https://github.com/Silv3rHorn/evtx2json/releases). 

Else, install from [requirements](https://github.com/Silv3rHorn/evtx2json/blob/master/requirements.txt) - `pip install -r requirements.txt`.

## Usage
```
evtx2json [-h] [-d DIR] [-f FILE] [-c CAT] [-o OUTPUT] [--evtxtract] [--thorough] [--nodedup] [--nodescr]

evtx2json extracts supported events from evtls, dedups them, and exports them to json.

Supported Windows Event Logs:
         all below                                                               all
         Security                                                                sec
         System                                                                  sys
         Application                                                             app
         Microsoft-Windows-Application-Experience/Program-Inventory              appexp1
         Microsoft-Windows-Application-Experience/Program-Telemetry              appexp2
         Microsoft-Windows-AppLocker/EXE and DLL                                 applocker
         Microsoft-Windows-Bits-Client/Operational                               bits
         Microsoft-Windows-CodeIntegrity/Operational                             codeinteg
         Microsoft-Windows-Diagnostics-Performance/Operational                   diag
         Microsoft-Windows-DNS-Client/Operational                                dnsclient
         Microsoft-Windows-DNSServer/Analytical                                  dnsserver
         Microsoft-Windows-DriverFrameworks-UserMode/Operational                 driverfw
         Microsoft-Windows-Kernel-PnP/Configuration                              kernelpnp
         Microsoft-Windows-NetworkProfile/Operational                            networkp
         Microsoft-Windows-Ntfs/Operational                                      ntfs
         Microsoft-Windows-OfflineFiles/Operational                              offlinef
         Microsoft-Windows-Partition/Diagnostic                                  partition
         Microsoft-Windows-PowerShell/Operational                                pshell2
         Microsoft-Windows-PrintService/Operational                              printsvc
         Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational           rdpcorets
         Microsoft-Windows-Shell-Core/Operational                                shell
         Microsoft-Windows-SmbClient/Security                                    smbclient
         Microsoft-Windows-SMBServer/Analytic                                    smbserver1
         Microsoft-Windows-SMBServer/Audit                                       smbserver2
         Microsoft-Windows-SMBServer/Connectivity                                smbserver3
         Microsoft-Windows-SMBServer/Operational                                 smbserver4
         Microsoft-Windows-SMBServer/Security                                    smbserver5
         Microsoft-Windows-Storage-ClassPnP/Operational                          scpnp
         Microsoft-Windows-StorageSpaces-Driver/Operational                      storspaces
         Microsoft-Windows-Storsvc/Diagnostic                                    storsvc
         Microsoft-Windows-TaskScheduler/Operational                             sch
         Microsoft-Windows-TerminalServices-LocalSessionManager/Operational      lsm
         Microsoft-Windows-TerminalServices-RDPClient/Operational                rdpclient
         Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational  rcm
         Microsoft-Windows-Windows Defender/Operational                          wdef
         Microsoft-Windows-Windows Firewall With Advanced Security/Firewall      fwall
         Microsoft-Windows-WinRM/Operational                                     winrm
         Microsoft-Windows-WLAN-AutoConfig/Operational                           wlan
         Microsoft-Windows-WMI-Activity/Operational                              wmi
         Symantec Endpoint Protection Client                                     symantec
         Windows PowerShell                                                      pshell1

optional arguments:
  -h, --help            show this help message and exit
  -d DIR, --dir DIR     directory to recursively process. Either this or -f is required
  -f FILE, --file FILE  file to process. Either this or -d is required
  -c CAT, --cat CAT     category of event logs to process. Separate multiple categories with a comma.
  -o OUTPUT, --output OUTPUT
                        path to the directory to store the output.
  --evtxtract           file(s) to process is evtxtract output
  --alternate           use python-evtx library instead (slower)
  --nodedup             skip de-duplication of events.
  --nodescr             excludes event description for faster and smaller output.
```

## Credits
Libraries
- Willi Ballenthin's [python-evtx](https://github.com/williballenthin/python-evtx)
- Omer BenAmram's [pyevtx-rs](https://github.com/omerbenamram/pyevtx-rs)

Code References
- JPCERTCC's [LogonTracer](https://github.com/JPCERTCC/LogonTracer)
