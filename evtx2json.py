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
import types

import evtl_selector as es
import evtxtract_formatter as ef

from resources import events, message_table
from datetime import datetime as dt
from evtx import PyEvtxParser
from Evtx import BinaryParser
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from lxml import etree

IS_FROZEN = getattr(sys, 'frozen', False)
FROZEN_TEMP_PATH = getattr(sys, '_MEIPASS', '')

LOG_FILE = ''
OPTIONS = types.SimpleNamespace()
PARSED_RECORDS = {}


def xml_records(filename):
    if OPTIONS.alternate:
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
    else:
        parser = PyEvtxParser(filename)
        try:
            for record in parser.records():
                try:
                    yield ef.to_lxml(record['data']), None
                except etree.XMLSyntaxError as e:
                    yield record['data'], e
        except Exception as e:  # UnicodeDecodeError, AttributeError, RuntimeError
            logging.error(e)
            yield None, e


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))


def _query_db(query):
    if IS_FROZEN:
        db_path = os.path.join(FROZEN_TEMP_PATH, "resources", "evtx2json.db")
    else:
        db_path = os.path.abspath("resources\\evtx2json.db")

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        conn.close()
    except (sqlite3.Error, IndexError):
        rows = None
        logging.error("SQLite: {0}".format(query))

    return rows


# map values to message in message_table.py
def _map_to_message(string):
    mapped_messages = []
    messages = re.findall(r"[\d']+", string)
    for message in messages:
        mapped_messages.append(message_table.mapping[message])

    return ', '.join(mapped_messages)


def _parse_event(node, channel, supported_events):
    event = dict()
    event['**Timestamp'] = node.xpath("/Event/System/TimeCreated")[0].get("SystemTime").replace(' UTC', 'Z')
    event['*Channel'] = channel
    event['*Provider'] = node.xpath("/Event/System/Provider")[0].get("Name")
    event['*Hostname'] = node.xpath("/Event/System/Computer")[0].text
    event['*SID'] = node.xpath("/Event/System/Security")[0].get("UserID")
    event['*EventID'] = int(node.xpath("/Event/System/EventID")[0].text)
    event['*RecordID'] = int(node.xpath("/Event/System/EventRecordID")[0].text)

    level = int(node.xpath("/Event/System/Level")[0].text)
    keywords = node.xpath("/Event/System/Keywords")[0].text
    # mapping level values to String
    if level == 0:
        if keywords[4] == 1:
            event['*Level'] = "Audit Failure"
        elif keywords[4] == 2:
            event['*Level'] = "Audit Success"
        else:
            event['*Level'] = '0'
    elif level == 1:
        event['*Level'] = "Audit Failure"
    elif level == 2:
        event['*Level'] = 'Error'
    elif level == 3:
        event['*Level'] = 'Warning'
    elif level == 4:
        event['*Level'] = 'Information'
    elif level == 5:
        event['*Level'] = 'Verbose'

    event_data = node.xpath("/Event/EventData/Data")

    fields = supported_events[event['*EventID']]
    try:
        if fields["Provider"].lower() != event['*Provider'].lower():
            return None
        if not OPTIONS.nodescr:
            event['*Descr'] = fields["Descr"]
    except KeyError as e:
        if 'Provider' not in str(e):
            logging.error("Key Error: {0}, {1}, {2}".format(event['*Channel'], event['*EventID'], str(e)))
        else:
            pass
    se_keys = list(fields.keys())
    se_keys = [key for key in se_keys if key not in ('Descr', 'Provider')]

    if len(event_data) > 0:
        for data in event_data:
            if data.get("Name") is None:
                event['Data'] = data.text
            elif data.get("Name") in se_keys:
                field_value = fields[data.get("Name")]
                if field_value[0] == '+':  # '+' is and indicator to convert value with database
                    field_value = field_value[1:]
                    field_value_new = field_value + '+'
                    query = "SELECT decode.decoded FROM decode LEFT JOIN eventid ON decode.eventid = eventid.id " \
                            "LEFT JOIN channel ON eventid.channel = channel.id WHERE channel.channel = '" + \
                            channel + "'" + " AND eventid.eventid LIKE '%" + str(event['*EventID']) + "%'" + \
                            " AND decode.fieldname = '" + data.get("Name") + "'" + \
                            " AND decode.value = '" + data.text + "'"
                    rows = _query_db(query)
                    try:
                        event[field_value_new] = rows[0][0]
                    except IndexError:
                        event[field_value_new] = data.text
                        if data.text != '0' and data.text != '0x00000000':
                            logging.error("Index Error: {0}".format(query))
                    except TypeError:  # rows = None (SQLite query failed)
                        event[field_value_new] = data.text

                if data.text and '%%' in data.text:
                    try:
                        event[field_value] = _map_to_message(data.text)
                    except KeyError:
                        event[field_value] = data.text
                else:
                    event[field_value] = data.text
    else:
        parent = "/Event/UserData/*/"

        for key, field_value in fields.items():
            if key in ('Descr', 'Provider'):
                continue
            path = parent + key
            try:
                if field_value[0] == '+':
                    field_value = field_value[1:]
                    field_value_new = field_value + '+'
                    query = "SELECT decode.decoded FROM decode LEFT JOIN eventid ON decode.eventid = eventid.id " \
                            "LEFT JOIN channel ON eventid.channel = channel.id WHERE channel.channel = '" + \
                            channel + "'" + " AND eventid.eventid LIKE '%" + str(event['*EventID']) + "%'" + \
                            " AND decode.fieldname = '" + key + "'" + \
                            " AND decode.value = '" + node.xpath(path)[0].text + "'"
                    rows = _query_db(query)
                    try:
                        event[field_value_new] = rows[0][0]
                    except (TypeError, IndexError):  # SQLite query failed)
                        event[field_value_new] = node.xpath(path)[0].text
                if node.xpath(path)[0].text and '%%' in node.xpath(path)[0].text:
                    event[field_value] = _map_to_message(node.xpath(path)[0].text)
                else:
                    event[field_value] = node.xpath(path)[0].text
            except KeyError:
                event[field_value] = node.xpath(path)[0].text
            except IndexError:
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
            count_found = 0
            count_processed = 0

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

                count_found += 1
                if not count_found % 100:
                    sys.stdout.write("\r[*] %i records found." % count_found)
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
                    count_processed += 1
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
                print("\r[*] {0} records found, {1} records processed\n".format(count_found, count_processed))
                logging.info("{0} records found, {1} records processed\n".format(count_found, count_processed))
            if not OPTIONS.evtxtract and channel is None and count_found == 0:
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
