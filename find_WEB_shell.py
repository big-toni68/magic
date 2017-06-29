import requests
import re
import os
import time
import json

params = {'apikey':'fb353fabed68add92f8a1d44089df0ebb42730cf6ee0a7d9d967feb5651f83ec'}


def get_report(filename):
    files = {'file': (filename, open(filename, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    params['resource'] = response.json()['sha256']
    headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  requests-python"
    }
    time.sleep(70)
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
    params=params, headers=headers)
    response = response.json()
    counter = 0
    try:
        for i in list(response['scans'].keys()):
            if response['scans'][i]['detected'] == True:
                counter +=1
    except KeyError:
        return(response['verbose_msg'])
    return('number of detection file {0}: {1}'.format(filename,counter))

#print(get_report(filename))

def GetListFiles(PathForBackup):
    ListFiles = []
    for file in os.listdir(PathForBackup):
        path = os.path.join(PathForBackup, file)
        if os.path.isfile(path):
            if re.findall('[^ ]+\.php',path):
                ListFiles.append(path)
        else:
            ListFiles += GetListFiles(path)
    return ListFiles

#print(get_report('/home/user/web_shell/KAdot_Universal_Shell_v0.1.6.php'))
try:
    for i in GetListFiles('/home/user/web_shell/'):
        print(get_report(i))
except Exception:
    pass
