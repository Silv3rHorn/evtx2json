from __future__ import print_function
import argparse
import os

from argparse import RawTextHelpFormatter

EVTX_HEADER = b"\x45\x6C\x66\x46\x69\x6C\x65\x00"
LOGS = []
CHANNEL_NAMES = {'appexp1': "Microsoft-Windows-Application-Experience/Program-Inventory",
                 'appexp2': "Microsoft-Windows-Application-Experience/Program-Telemetry",
                 'applocker': "Microsoft-Windows-AppLocker/EXE and DLL",
                 'bits': "Microsoft-Windows-Bits-Client/Operational",
                 'diag': "Microsoft-Windows-Diagnostics-Performance/Operational",
                 'dns': "Microsoft-Windows-DNSServer/Analytical",
                 'fwall': "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                 'lsm': "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                 'offlinef': "Microsoft-Windows-OfflineFiles/Operational",
                 'pshell1': "Windows PowerShell", 'pshell2': "Microsoft-Windows-PowerShell/Operational",
                 'rcm': "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                 'rdpclient': "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                 'rdpcorets': "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
                 'sch': "Microsoft-Windows-TaskScheduler/Operational", 'sec': "Security", 'sys': "System",
                 'shell': "Microsoft-Windows-Shell-Core/Operational",
                 'smbclient': "Microsoft-Windows-SmbClient/Security",
                 'symantec': "Symantec Endpoint Protection Client",
                 'wdef': "Microsoft-Windows-Windows Defender/Operational",
                 'winrm': "Microsoft-Windows-WinRM/Operational",
                 'wmi': "Microsoft-Windows-WMI-Activity/Operational"}


def _check_file(fpath, is_xml):
    if is_xml:
        return True

    if fpath.endswith('evtx'):
        with open(os.path.join(fpath), 'rb') as infile:
            header = infile.read()[0:8]
            if header == EVTX_HEADER:
                return True
    return False


def _validate_input(options):
    if (options.dir is None and options.file is None) or (options.dir and options.file):
        print(options.dir, options.file)
        print("Please specify either a file or a directory to process!")
        return False

    if options.file and os.path.isfile(options.file):
        if _check_file(options.file, options.evtxtract):
            LOGS.append(options.file)

    if options.dir and os.path.isdir(options.dir):
        for root, subdirs, files in os.walk(options.dir):
            for f in files:
                if _check_file(os.path.join(root, f), options.evtxtract):
                    LOGS.append(os.path.join(root, f))

    if len(LOGS) == 0:
        return False
    return True


def _parse_selection(logs):
    supported = (set(CHANNEL_NAMES.keys())) | {'all'}

    selection = logs.split(',')
    selection = set(selection)

    # remove unsupported artifacts
    unsupported = set()
    for selected in selection:
        if selected not in supported:
            print("{} artifact is not supported.\n".format(selected))
            unsupported.add(selected)
    selection = selection - unsupported

    # expand 'all'
    if 'all' in selection:
        selection = selection | supported

    # remove 'all'
    selection = selection - {'all'}

    selection = list(selection)
    if len(selection) > 0:
        for i in range(len(selection)):
            selection[i] = CHANNEL_NAMES[selection[i]]
    else:
        selection = None

    return selection


def get_selection():
    argument_parser = argparse.ArgumentParser(description=(
        'evtx2json extracts supported events from evtls, dedups them, and exports them to json.\n\n'

        'Supported Windows Event Logs: \n'
        '\t all below                                                               all \n'
        '\t Security                                                                sec \n'
        '\t System                                                                  sys \n'
        '\t Microsoft-Windows-Application-Experience/Program-Telemetry              appexp \n'
        '\t Microsoft-Windows-AppLocker/EXE and DLL                                 applocker \n'
        '\t Microsoft-Windows-Bits-Client/Operational                               bits \n'
        '\t Microsoft-Windows-Diagnostics-Performance/Operational                   diag \n'
        '\t Microsoft-Windows-DNSServer/Analytical                                  dns \n'
        '\t Microsoft-Windows-OfflineFiles/Operational                              offlinef \n'
        '\t Microsoft-Windows-PowerShell/Operational                                pshell2 \n'
        '\t Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational           rdpcorets \n'
        '\t Microsoft-Windows-Shell-Core/Operational                                shell \n'
        '\t Microsoft-Windows-SmbClient/Security                                    smbclient \n'
        '\t Microsoft-Windows-TaskScheduler/Operational                             sch \n'
        '\t Microsoft-Windows-TerminalServices-LocalSessionManager/Operational      lsm \n'
        '\t Microsoft-Windows-TerminalServices-RDPClient/Operational                rdpclient \n'
        '\t Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational  rcm \n'
        '\t Microsoft-Windows-Windows Defender/Operational                          wdef \n'
        '\t Microsoft-Windows-Windows Firewall With Advanced Security/Firewall      fwall \n'
        '\t Microsoft-Windows-WinRM/Operational                                     winrm \n'
        '\t Microsoft-Windows-WMI-Activity/Operational                              wmi \n'
        '\t Symantec Endpoint Protection Client                                     symantec \n'
        '\t Windows PowerShell                                                      pshell1 \n'
    ), formatter_class=RawTextHelpFormatter)

    argument_parser.add_argument('-d', '--dir', default=None, help=(
        "directory to recursively process. Either this or -f is required"))
    argument_parser.add_argument('-f', '--file', default=None, help=(
        "file to process. Either this or -d is required"))
    argument_parser.add_argument('-c', '--cat', default='all', help=(
        "category of event logs to process. Separate multiple categories with a comma."))
    argument_parser.add_argument('-o', '--output', default=os.getcwd(), help=(
        "path to the directory to store the output."))
    argument_parser.add_argument('--evtxtract', action='store_true', help="file(s) to process is evtxtract output")
    argument_parser.add_argument('--dedup', action='store_true', help="de-duplicate events.")

    options = argument_parser.parse_args()

    if not _validate_input(options):
        return False

    if options.dir is not None:
        options.dir = os.path.abspath(options.dir)
    if options.file is not None:
        options.file = os.path.abspath(options.file)
    options.output = os.path.abspath(options.output)

    options.cat = _parse_selection(options.cat)
    if options.cat is None:
        return False
    else:
        return options
