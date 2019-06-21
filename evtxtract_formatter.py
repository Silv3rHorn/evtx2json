import re
import xml.etree.ElementTree as Et

from lxml import etree
from tempfile import NamedTemporaryFile


def _sanitise_xml(original):
    with open(original, 'r') as infile:
        with NamedTemporaryFile(delete=False, mode='w+') as outfile:
            temp_name = outfile.name
            for line in infile:
                line = re.sub(r'((\x00)|\x5c&([lg]t|amp))+', '', line)  # null | \&lt | \&gt | \&amp
                line = re.sub(r'\\([-/%])', r'\1', line)
                outfile.write(line)
    return temp_name


def _list_to_generator(list_to_convert):
    for item in list_to_convert:
        yield item, None


def to_lxml(record_xml):
    record_xml = record_xml.replace("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n", '', 1)
    rep_xml = re.sub(r' xmlns(:auto.*)?=\".+?\"', '', record_xml)  # xmlns="*" or xmlns:auto*="*"
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
