import re
from tqdm import tqdm
import time
import subprocess


class Profiler(object):
    def __enter__(self):
        self._startTime = time.time()

    def __exit__(self, type, value, traceback):
        print("Elapsed time: {:.3f} sec".format(time.time() - self._startTime))


class parse_log:
    def __init__(self,path_log_file):

        self.path_log_file = path_log_file
        self.dict_attack = dict(XSS=[
            "(?i)(<script[^>]*>[\s\S]*?<\/script[^>]*>|<script[^>]*>[\s\S]*?<\/script[[\s\S]]*[\s\S]|<script[^>]*>[\s\S]*?<\/script[\s]*[\s]|<script[^>]*>[\s\S]*?<\/script|<script[^>]*>[\s\S]*?)",
            "(<script|javascript:|function\(\)|iframe|onerror|onmouseover|onload)",])
        self.dict_attack[
            'Path_Traversal'] = '(?:(?:\\\\|\\/)?(?:(?:\\.){2,4}|(?:\\xc0\\xae){1,2}|(?:\\xc0\\xaf){1,2}|(?:\\xc1\\x9c){1,2}|(?:\\xc1\\x1c){1,2}|(?:\\xc1\\xaf){1,2})(?:\\\\|\\/)|^[\\s\\.\\/\\\\]*(?:\\/(?:etc\\/|var\\/|root\\/|usr\\/|proc\\/|opt\\/|srv\\/|boot\\/|tmp\\/|logs\\/|home\\/|www\\/|Volumes\\/|Library\\/|private\\/|system\\/|web\\/|bin\\/|apache2?\\/|http\\/|(?i:wamp\\/)|(?i:xampp\\/)|(?i:windows\\/)|(?i:winnt\\/)|mysql\\/|(?i:php)\\d?\\/|WEB-INF\\/|static\\/WEB-INF\\/|(?i:program*)(?:\\~\\d\\/|(?i: files\\/)))|\\/?\\w:(?:\\/|\\\\))[\\[\\]\\w\\s\\d\\/\\-\\._\\{\\}~]*(?:\\/?[\\-\\_\\w\\d\\.]+)(?:~|-)?\\s*(?:[:\\s\\x00]|$)|^(?:\\w:)?\\\\?\\\\[\\w\\s\\d\\.\\?]+\\\\|^(?:\\/|\\w:\\/)[-_\\w\\d\\.]+\\.(?:conf(?:ig)?|logs?|allow|deny|bashrc|defs|cnf|crt|cer|soap|ini|bak|old|backup)(?:~|-)?(?:$|\\x00))'
        self.dict_attack[
            'OS_Injection'] = '(?:\\b(?:(?:n(?:et(?:\\b\\W+?\\blocalgroup|\\.exe)|(?:map|c)\\.exe)|t(?:racer(?:oute|t)|elnet\\.exe|clsh8?)|(?:w(?:guest|sh)|rcmd|ftp)\\.exe|echo\\b\\W*?\\by+)\\b|c(?:md(?:(?:\\.exe|32)\\b|\\b\\W*?\\/c)|d(?:\\b\\W+?[\\\\/]|\\W+?\\.\\.)|hmod.{0,40}?\\+.{0,3}x)))'
        self.dict_attack['SQL_Injection'] = '(union|waitfor|pg_sleep|char\(\d+\)|chr\(\d+\)|select|from|order|sby|benchmark|sleep|null|or\s|and\s|declare)'
        self.dict_attack['XXE']='(<!ENTITY)'
        self.dict_attack['ShellShock'] = "\(\)(+|\s){)"
        self.bad_user_agent = 'havij|netsparker|dirbuster|w3af|sqlmap|acunetix|nmap|ninja|nessus|openvas|wpscan|webinspect|qualys|fiddler|python-requests|sucuri|bsqlbf|burpcollaborator|fiddler'
        self.scan = '\.\S*\s*\sHTTP.*\s404'

    def counter_attack(self):
        count_dict = {'XSS':0,'SQL':0,'OS_command':0,'Path_Traversal':0,'XXE':0,'ShellShock':0}
        #count_XSS, count_SQL, count_OS_command, count_Path_Traversal, count_XXE, count_ShellShock = [0 for x in range(6)]
        XSS_pattern = [re.compile(self.dict_attack['XSS'][i]) for i in range(len(self.dict_attack['XSS']))]
        SQL_pattern = re.compile(self.dict_attack['SQL_Injection'], re.I)
        OS_Injection_pattern = re.compile(self.dict_attack['OS_Injection'])
        Path_Traversal_pattern = re.compile(self.dict_attack['Path_Traversal'])
        XXE_pattern = re.compile(self.dict_attack['XXE'])
        ShellShock_pattern = re.compile(self.dict_attack['ShellShock'])
        with open(self.path_log_file) as f:
            for string in f:
                if XSS_pattern[0].search(string) or XSS_pattern[1].search(string):
                    count_dict['XSS'] += 1
                    continue
                elif SQL_pattern.search(string):
                    count_dict['SQL'] += 1
                    continue
                elif Path_Traversal_pattern.search(string):
                    count_dict['Path_Traversal'] += 1
                    continue
                elif OS_Injection_pattern.search(string):
                    count_dict['OS_command'] += 1
                    continue
                elif XXE_pattern.search(string):
                    count_dict['XXE'] +=1
                    continue
                elif ShellShock_pattern.search(string):
                    count_dict['ShellShock'] +=1
        for i in count_dict:
            print("number of {0}: {1}".format(i,count_dict[i]))
        #print("Number of XSS: {0}".format(count_XSS))
        #print("Number of SQL: {0}".format(count_SQL))
        #print("Number of Path Traversal: {0}".format(count_Path_Traversal))
        #print("Number of Path OS Injection Attack: {0}".format(count_OS_command))
        #print("Number of XXE attack: {0}".format(count_XXE))

    def find_scan(self):
        count_bad_user_agent, count_scan = 0, 0
        with open(self.path_log_file) as f:
            user_agent_pattern = re.compile(self.bad_user_agent,re.IGNORECASE)
            scan_pattern = re.compile(self.scan)
            for string in f:
                if user_agent_pattern.search(string):
                    count_bad_user_agent += 1
                elif scan_pattern.search(string):
                    count_scan += 1

        print("Number of Bad User_agent: {0}".format(count_bad_user_agent))
        print("Number of Not Found: {0}".format(count_scan))

    def get_list_ip(self):
        result = str(subprocess.check_output("cat {0} | cut -d ' ' -f1|sort|uniq -c|sort -n |wc -l ".format(self.path_log_file),stderr=subprocess.STDOUT,shell = True))
        result = ''.join(re.findall('[0-9]',result))
        print("number of unique ip`s: {0} ".format(result))

    def get_request_type(self):
        result = str(subprocess.check_output("cat {0}|cut -d ' ' -f6|sort|uniq -c|sort -n".format(self.path_log_file), stderr=subprocess.STDOUT, shell = True))
        list_count = re.findall('\d+',result)
        list_method = re.findall(('[A-Z]+'),result)
        if len(list_method)!=len(list_count):
            raise  IOError('error of length')
        else:
            for i in range(len(list_count)):
                print("number of type requests {0}: {1}".format(list_method[i],list_count[i]))

    def get_uniq_url(self):
        result = str(subprocess.check_output('''cut -d '"' -f2 {0}|sort|uniq -c|sort -n|wc -l'''.format(self.path_log_file),stderr=subprocess.STDOUT,shell =True))
        result = re.findall('\d+',result)[0]
        print("number of uniq url`s - {0}".format(result))

result = parse_log("/home/user/logs/hq.weblab.megafon.ru.access_log20150110")
with Profiler() as p:
    result.get_uniq_url()




