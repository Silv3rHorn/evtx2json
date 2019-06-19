#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to filter events, decode fields, and export evtx to json log format."""

from __future__ import print_function
import json
import logging
import mmh3
import os
import re
import sqlite3
import sys

import events
import evtl_selector as es
import evtxtract_formatter as ef
import message_table

from datetime import datetime as dt
from Evtx import BinaryParser
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from lxml import etree

LOG_FILE = ''
OPTIONS = None
PARSED_RECORDS = {}


def xml_records(filename):
    with Evtx(filename) as evtx:
        try:
            for xml, record in evtx_file_xml_view(evtx.get_file_header()):
                try:
                    yield ef.to_lxml(xml), None
                except etree.XMLSyntaxError as e:
                    yield xml, e
        except BinaryParser.OverrunBufferException as e:
            logging.error("Overrun Buffer Exception!")
            yield None, e
        except BinaryParser.ParseException as e:
            logging.error("Parse Exception!")
            yield None, e
        except Exception as e:  # UnicodeDecodeError, AttributeError
            logging.error(e)
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
    event['*Channel'] = channel
    event['*EventID'] = int(node.xpath("/Event/System/EventID")[0].text)
    event['*RecordID'] = int(node.xpath("/Event/System/EventRecordID")[0].text)
    event['*Timestamp'] = node.xpath("/Event/System/TimeCreated")[0].get("SystemTime")
    event['*Hostname'] = node.xpath("/Event/System/Computer")[0].text
    event['*SID'] = node.xpath("/Event/System/Security")[0].get("UserID")
    event_data = node.xpath("/Event/EventData/Data")

    fields = supported_events[event['*EventID']]
    se_keys = list(fields.keys())
    if not OPTIONS.nodescr:
        event['*Descr'] = fields["Descr"]

    if len(event_data) > 0:
        for data in event_data:
            # TODO: check if data is empty
            if data.get("Name") is None:
                event['Data'] = data.text
            elif data.get("Name") in se_keys:
                field_value = fields[data.get("Name")]
                if field_value[0] == '+':  # '+' is and indicator to convert value with database
                    field_value = field_value[1:]
                    query = ''
                    try:
                        conn = sqlite3.connect('evtx2json.db')
                        cur = conn.cursor()
                        query = "SELECT decode.decoded FROM decode LEFT JOIN eventid ON decode.eventid = eventid.id " \
                                "LEFT JOIN channel ON eventid.channel = channel.id WHERE channel.channel = '" + \
                                channel + "'" + " AND eventid.eventid LIKE '%" + str(event['*EventID']) + "%'" + \
                                " AND decode.fieldname = '" + data.get("Name") + "'" + \
                                " AND decode.value = '" + data.text + "'"
                        cur.execute(query)
                        rows = cur.fetchall()
                        event[field_value] = rows[0][0]
                        conn.close()
                    except (sqlite3.Error, IndexError):
                        event[field_value] = data.text
                        if data.text != '0' and data.text != '0x00000000':
                            logging.error("SQLite/Index Error: {0}".format(query))
                elif data.text and '%%' in data.text:
                    try:
                        event[field_value] = _map_to_message(data.text)
                    except KeyError:
                        event[field_value] = data.text

                else:
                    event[field_value] = data.text
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
            except IndexError:
                if key != "Descr":
                    logging.error("Index Error: {0}, {1}, {2}".format(event['*Channel'], event['*EventID'], key))

    return json.dumps(event)


def _isdup(parsed_output, channel):
    record_hash = hex(mmh3.hash(parsed_output))
    if record_hash in PARSED_RECORDS[channel]:
        return True
    else:
        PARSED_RECORDS[channel].add(record_hash)
        return False


def run(output_path):
    with open(output_path, 'a') as outfile:
        for log in es.LOGS:
            print("\rInput file: {}".format(log))
            logging.info("Input file: {}".format(log))

            channel = None
            event_id = None
            supported_events = []
            count = 0

            if OPTIONS.evtxtract:
                nodes = ef.get_log(log)
            else:
                nodes = xml_records(log)

            for node, err in nodes:
                if err is not None:
                    continue  # skip record

                if OPTIONS.evtxtract:
                    channel = None
                    event_id = None

                if channel is None:  # for xml, channel can vary for each record in log
                    for _ in node.xpath("/Event/System/Channel"):  # get channel
                        channel = node.xpath("/Event/System/Channel")[0].text
                    if channel not in OPTIONS.cat:  # if event log not selected by user
                        if OPTIONS.evtxtract:
                            continue
                        else:
                            print("\r{}\n".format("Not selected by user!"))
                            logging.info("{}\n".format("Not selected by user!"))
                            break

                count += 1
                if not count % 100:
                    sys.stdout.write("\r[*] %i records processed." % count)
                    sys.stdout.flush()

                if OPTIONS.evtxtract or len(supported_events) == 0:  # get supported events of event log
                    evtl_name = list(es.CHANNEL_NAMES.keys())[list(es.CHANNEL_NAMES.values()).index(channel)]
                    supported_events = getattr(events, evtl_name)

                for _ in node.xpath("/Event/System/EventID"):
                    try:
                        event_id = int(node.xpath("/Event/System/EventID")[0].text)
                    except TypeError:  # e.g. None
                        event_id = -1
                        continue

                if event_id not in supported_events:
                    continue  # skip record

                parsed_record = _parse_event(node, channel, supported_events)
                if parsed_record:
                    if not OPTIONS.nodedup:
                        if not _isdup(parsed_record, channel):
                            outfile.write(parsed_record)
                            outfile.write('\r')
                    else:
                        outfile.write(parsed_record)
                        outfile.write('\r')
            # flush buffered output to file
            outfile.flush()
            os.fsync(outfile)

            if OPTIONS.evtxtract or channel in OPTIONS.cat:
                print("\r[*] {} records processed!\n".format(count))
                logging.info("{} records processed!\n".format(count))
            if not OPTIONS.evtxtract and channel is None and count == 0:
                print("\rNo records in log!\n")
                logging.info("No records in log!\n")


def main():
    global OPTIONS, LOG_FILE

    start_time = dt.now()

    OPTIONS = es.get_selection()
    if not OPTIONS:
        return False

    timestamp = dt.now().strftime("%Y-%m-%d@%H%M%S")
    LOG_FILE = os.path.join(OPTIONS.output, "_evtx2json_log.{}.txt".format(timestamp))
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format=u'[%(levelname)s] %(message)s')

    # log all argument values
    for arg in dir(OPTIONS):
        if not arg.startswith('__') and not callable(getattr(OPTIONS, arg)):
            logging.info("{0}:\t{1}".format(arg, getattr(OPTIONS, arg)))

    global PARSED_RECORDS
    for selected in OPTIONS.cat:
        PARSED_RECORDS[selected] = set()

    output_path = os.path.join(OPTIONS.output, "evtx2json_{}.txt".format(timestamp))
    run(output_path)

    print("\rTime Taken: {}".format(dt.now() - start_time))
    logging.info("Time Taken: {}".format(dt.now() - start_time))


if __name__ == '__main__':
    if not main():
        sys.exit(1)
    else:
        sys.exit(0)
