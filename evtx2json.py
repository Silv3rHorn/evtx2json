#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to filter events, decode fields, and export evtx to json log format."""

from __future__ import print_function
import json
import logging
import mmh3
import os
import re
import sys

import evtl_selector as es
import events
import message_table

from datetime import datetime as dt
from Evtx import BinaryParser
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from lxml import etree

LOG_FILE = ''
PARSED_RECORDS = {}


def to_lxml(record_xml):
    rep_xml = record_xml.replace("xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"", "")
    rep_xml = rep_xml.replace("xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\"", "")
    rep_xml = rep_xml.replace("xmlns=\"http://manifests.microsoft.com/win/2006/windows/WMI\"", "")
    rep_xml = rep_xml.replace("xmlns=\"Event_NS\"", "")
    set_xml = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" % rep_xml
    fin_xml = set_xml.encode("utf-8")
    return etree.fromstring(fin_xml)


def xml_records(filename):
    with Evtx(filename) as evtx:
        try:
            for xml, record in evtx_file_xml_view(evtx.get_file_header()):
                try:
                    yield to_lxml(xml), None
                except etree.XMLSyntaxError as e:
                    yield xml, e
        except UnicodeDecodeError as e:
            logging.error("Unicode Decode Error!")
            yield None, e
        except BinaryParser.OverrunBufferException as e:
            logging.error("Overrun Buffer Exception!")
            yield None, e
        except BinaryParser.ParseException as e:
            logging.error("Parse Exception!")
            yield None, e


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))


def _map_to_message(string):
    mapped_messages = []
    messages = re.findall(r"[\d']+", string)
    for message in messages:
        mapped_messages.append(message_table.mapping[message])

    return ', '.join(mapped_messages)


def _parse_event(node, channel, supported_events):
    event = dict()
    event['RecordID'] = int(node.xpath("/Event/System/EventRecordID")[0].text)
    event['EventID'] = int(node.xpath("/Event/System/EventID")[0].text)
    event['Timestamp'] = node.xpath("/Event/System/TimeCreated")[0].get("SystemTime")
    event['Hostname'] = node.xpath("/Event/System/Computer")[0].text
    event['SID'] = node.xpath("/Event/System/Security")[0].get("UserID")
    event['Channel'] = channel

    fields = supported_events[event['EventID']]
    se_keys = list(fields.keys())
    event_data = node.xpath("/Event/EventData/Data")

    if len(event_data) > 0:
        for data in event_data:
            # TODO: check if data is empty
            if data.get("Name") is None:
                event['Data'] = data.text
            elif data.get("Name") in se_keys:
                try:
                    if data.text and '%%' in data.text:
                        event[fields[data.get("Name")]] = _map_to_message(data.text)
                    else:
                        event[fields[data.get("Name")]] = data.text
                except KeyError:
                    event[fields[data.get("Name")]] = data.text
    else:
        parent = "/Event/UserData/*/"

        for key, value in fields.items():
            path = parent + key
            try:
                if node.xpath(path)[0].text and '%%' in node.xpath(path)[0].text:
                    event[value] = _map_to_message(node.xpath(path)[0].text)
                else:
                    event[value] = node.xpath(path)[0].text
            except KeyError:
                event[value] = node.xpath(path)[0].text

    return json.dumps(event)


def _isdup(parsed_output, channel):
    record_hash = hex(mmh3.hash(parsed_output))
    if record_hash in PARSED_RECORDS[channel]:
        return True
    else:
        PARSED_RECORDS[channel].add(record_hash)
        return False


def _write_to_file(dest, to_write):
    with open(dest, 'a') as outfile:
        for item in to_write:
            outfile.write(item)
            outfile.write('\r')


def run(options):
    for log in es.LOGS:
        to_write = []
        print(u"\rInput file: {}".format(log))
        logging.info(u"Input file: {}".format(log))

        channel = None
        supported_events = []
        count = 0

        for node, err in xml_records(log):
            if err is not None:
                continue  # skip record

            if channel is None:
                channel = node.xpath("/Event/System/Channel")[0].text
                if channel not in options.cat:  # if event log not selected by user
                    print("\r{}\n".format("Not selected by user!"))
                    logging.info("{}\n".format("Not selected by user!"))
                    break  # skip event log

            count += 1
            if not count % 100:
                sys.stdout.write("\r[*] %i records processed." % count)
                sys.stdout.flush()

            if len(supported_events) == 0:  # get supported events of event log
                evtl_name = list(es.CHANNEL_NAMES.keys())[list(es.CHANNEL_NAMES.values()).index(channel)]
                supported_events = getattr(events, evtl_name)

            event_id = int(node.xpath("/Event/System/EventID")[0].text)
            if event_id not in supported_events:
                continue  # skip record

            parsed_output = _parse_event(node, channel, supported_events)
            if parsed_output:
                if options.dedup:
                    if not _isdup(parsed_output, channel):
                        to_write.append(parsed_output)
                else:
                    to_write.append(parsed_output)

        if channel in options.cat:
            print("\r[*] {} records processed!\n".format(count))
            logging.info("{} records processed!\n".format(count))
        if channel is None and count == 0:
            print("\rNo records in log!\n")
            logging.info("No records in log!\n")

        _write_to_file(os.path.join(options.output, 'evtxport_output.json'), to_write)


def main():
    start_time = dt.now()

    options = es.get_selection()
    if not options:
        return False

    global LOG_FILE
    timestamp = dt.now()
    LOG_FILE = os.path.join(options.output, "_evtxport_log.{}.txt".format(timestamp.strftime("%Y-%m-%d@%H%M%S")))
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format=u'[%(levelname)s] %(message)s')
    for arg in dir(options):
        if not arg.startswith('__') and not callable(getattr(options, arg)):
            logging.info(u"{0}:\t{1}".format(arg, getattr(options, arg)))

    global PARSED_RECORDS
    for selected in options.cat:
        PARSED_RECORDS[selected] = set()

    run(options)
    print("\rTime Taken: {}".format(dt.now()-start_time))
    logging.info("Time Taken: {}".format(dt.now()-start_time))


if __name__ == '__main__':
    if not main():
        sys.exit(1)
    else:
        sys.exit(0)
