import re
import xml.etree.ElementTree as Et

from lxml import etree
from tempfile import NamedTemporaryFile


def _sanitise_xml(original):
    with open(original, 'r') as infile:
        with NamedTemporaryFile(delete=False) as outfile:
            temp_name = outfile.name
            for line in infile:
                line = re.sub(r'(\x00|\x5c&[lg]t)+', '', line)
                line = line.replace('\-', '-')
                line = line.replace('\/', '/')
                outfile.write(line)
    return temp_name


def _list_to_generator(list_to_convert):
    for item in list_to_convert:
        yield item, None


def to_lxml(record_xml):
    rep_xml = record_xml.replace("xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"", "")
    rep_xml = rep_xml.replace("xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\"", "")
    rep_xml = rep_xml.replace("xmlns=\"http://manifests.microsoft.com/win/2006/windows/WMI\"", "")
    rep_xml = rep_xml.replace("xmlns=\"Event_NS\"", "")
    set_xml = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" % rep_xml
    fin_xml = set_xml.encode("utf-8")
    return etree.fromstring(fin_xml)


def _remove_namespace(root):
    for index, node in enumerate(root):
        node_string = Et.tostring(node).decode()
        node_string = re.sub(r"ns\d+:", '', node_string)
        node_string = re.sub(r":ns\d+", '', node_string)
        root[index] = to_lxml(node_string)
    return root


def get_log(log):
    log = _sanitise_xml(log)
    tree = Et.parse(log)
    root = tree.getroot()
    return _list_to_generator(_remove_namespace(root))
