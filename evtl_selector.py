from __future__ import print_function
import argparse
import os

from argparse import RawTextHelpFormatter

EVTX_HEADER = b"\x45\x6C\x66\x46\x69\x6C\x65\x00"
LOGS = []
CHANNEL_NAMES = {'bits': "Microsoft-Windows-Bits-Client/Operational",
                 'fwall': "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                 'lsm': "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                 'pshell': "Windows PowerShell", 'pshello': "Microsoft-Windows-PowerShell/Operational",
                 'rcm': "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                 'rdpclient': "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                 'rdpcorets': "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
                 'sch': "Microsoft-Windows-TaskScheduler/Operational", 'sec': "Security", 'sys': "System",
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
        '\t all \t\t all below\n'
        '\t sec \t\t Security\n'
        '\t sys \t\t System\n'
        '\t sch \t\t Microsoft-Windows-TaskScheduler/Operational\n'
        '\t lsm \t\t Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\n'
        '\t rcm \t\t Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational\n'
        '\t rdpclient \t Microsoft-Windows-TerminalServices-RDPClient/Operational\n'
        '\t rdpcorets \t Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational\n'
        '\t wdef \t\t Microsoft-Windows-Windows Defender/Operational\n'
        '\t fwall \t\t Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\n'
        '\t symantec \t Symantec Endpoint Protection Client\n'
        '\t pshell \t Windows PowerShell\n'
        '\t pashello \t Microsoft-Windows-PowerShell/Operational\n'
        '\t wmi \t\t Microsoft-Windows-WMI-Activity/Operational\n'
        '\t winrm \t\t Microsoft-Windows-WinRM/Operational\n'
        '\t bits \t\t Microsoft-Windows-Bits-Client/Operational\n'
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

    options.dir = os.path.abspath(options.dir)
    options.file = os.path.abspath(options.file)
    options.output = os.path.abspath(options.output)

    options.cat = _parse_selection(options.cat)
    if options.cat is None:
        return False
    else:
        return options
