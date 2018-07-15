from distutils.core import setup
from glob import glob
import py2exe
import sys

sys.path.append("D:\\Dropbox\\git\\msvcr90")
data_files = [("Microsoft.VC90.CRT", glob(r'D:\Dropbox\git\msvcr90\*.*'))]

setup(
    console=['evtx2json.py'],
    options={
        'py2exe':
        {
            'includes': ['lxml.etree', 'lxml._elementpath', 'gzip'],
        }
    },
    data_files=data_files
)
