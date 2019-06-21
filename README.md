# evtx2json
![](https://img.shields.io/badge/python-3.7-blue.svg)

evtx2json extracts **supported events** from event logs, **dedups** them, and exports them 
to json.

Also includes event description for each exported event.

## Why was this created?
To extract only events and fields **of interest** from multiple event logs, in
a format that is compatible for ingesting and querying with Splunk.

## Dependencies
None if using **release executable**. 

Else, install from [requirements](https://github.com/Silv3rHorn/evtx2json/blob/master/requirements.txt) - `pip install -r requirements.txt`.

## Usage
See `evtx2json -h` or `python evtx2json.py -h`

## Credits
Library
- Willi Ballenthin's [python-evtx](https://github.com/williballenthin/python-evtx)
- Omer BenAmram's [pyevtx-rs](https://github.com/omerbenamram/pyevtx-rs)

Code References - JPCERTCC's [LogonTracer](https://github.com/JPCERTCC/LogonTracer)
