# -*- mode: python -*-
import os
import platform

block_cipher = None


def get_resources():
    data_files = []
    for file_name in os.listdir('resources'):
        data_files.append((os.path.join('resources', file_name), 'resources'))
    return data_files


a = Analysis(['evtx2json.py'],
             pathex=['D:\\Dropbox\\git\\evtx2json'],
             binaries=[],
             datas=get_resources(),
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

pyz = PYZ(a.pure, a.zipped_data,
            cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='evtx2json',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
