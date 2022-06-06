import re
import socket
import sys
from datetime import datetime
import time
import tailer
import os
import requests



installpath = (sys.argv[1])
bn= sys.argv[2]
sendtoinflux = int(sys.argv[3])
IsGA = sys.argv[4]
release =  sys.argv[5]
box = sys.argv[6]

if os.path.exists("myfile.txt"):
    os.remove("myfile.txt")
################Function to calculate time difference and convert time##############################


def timeconversion(StringToTime):
    StringToTime = datetime.strptime(line[0:19], '%Y-%m-%d %H:%M:%S')
    return StringToTime
def get_seconds(diff, key):
    diff1=str(diff)
    hh, mm, ss = diff1.split(':')
    return (int(hh) * 3600 + int(mm) * 60 + int(ss))

def timecalculation(diff, key):
    hrs = int(diff.total_seconds() / 3600)
    mins = int((diff.total_seconds() % 3600) / 60)
    sec = int(diff.total_seconds() - (int(diff.total_seconds() / 3600)) * 3600 - (
        int((diff.total_seconds() % 3600) / 60)) * 60)
    # print("%stook %s Hours %s Minutes %s Seconds <BR> \n" % (    key, hrs, mins, sec))
    ValuesInSec[key]=get_seconds(diff, key)
    values[key] = ("%s Hours %s Minutes %s Seconds <BR> \n" % (hrs, mins, sec))

####################Variable declarations###########################################################
details= {}
count = False

exception1 = re.compile("(\d.*(ERROR|SEVERE).*\[)")
values = {
          "PDL_LICENSE ": "6",
          "PDL_FORGE ": "6",
          "PDL_COMPONENT ": "6",
          "PDL_COMPONENT_VERSION ": "6",
          "PDL_COMPONENT_LICENSE ": "6",
          "PDL_VULNERABILITY_REGISTRY ": "6",
          "PDL_VULNERABILITY ": "6",
          "PDL_COMP_VER_VULNERABILITY ": "6",
          "PDL_COMP_VER_LICENSE ": "6",
          "PDL_COMP_VER_METADATA ": "6",
          "PDL_COMP_VER_RELEASE ": "6",
          "PDL_OBLIGATION_ORGANIZATION ": "6",
          "PDL_OBLIGATION_PRIORITY ": "6",
          "PDL_OBLIGATION_TRIGGER_ACTION ": "6",
          "PDL_OBLIGATION_TYPE ": "6",
          "PDL_OBLIGATION ": "6",
          "PDL_LICENSE_OBLIGATION_MAP ": "6",
          "PDL_LICENSE_PATTERN ": "6",
          "PDL_AW_GROUPS ": "5",
          "PDL_AW_FILES ": "4",
          "PDL_COMPONENT_MAPPING ": "3",
          "PDL_LICENSE_DETECTION_XML ": "2",
          "PDL_VULNERABILITY_MAPPING ": "1",
		  "PDL_COMPONENT_CPE_MAP ": "0",
          "PDL_CVE_REFERENCES " : "0",
          "PDL_CWE " : "0",
          "PDL_VULNERABILITY_CWE_MAP " : "0",
          "Update completed...": "0"
}
ValuesInSec=values.copy()
a = []
timeout = time.time() + 72000 #1*60*60*5   # 5 minutes from now
# file = "D:\FlexNetCodeInsight\logs\core.log"
file = installpath + "/logs/core.log"

Start=0
allexceptions =[]

for line in tailer.follow(open(file)):
    if time.time() > timeout:
        print("Exiting PDL did not finish in 20 hours")
        f = open("myfile.txt", "w")
        f.write("Update did not complete in 20 hours; please check the log manually")
        sys.exit(0)
    if re.search(exception1,line):
        print("Following exceptions seen in logs: \n")
        print(line)
        allexceptions.append(line)
    for key in values.keys():
        if key in line:
            a.append(timeconversion(line[0:19]))
            values[key]=line[0:19]
            if key =="Update completed...":
                break;
            break
    if "[IndexBuilder] Total time for create" in line:
        ind = line[94:]
        break
temp =1
for key in values.keys():
    diff = a[temp] - a[temp - 1]
    # total = diff + total
    timecalculation(diff, key)
    temp = temp + 1
    if temp == 28:
        break


values["PDL indexing"] = ind + "<BR>"
timecalculation((a[len(a)-1]-a[0]),"Total Time")
del(values["Update completed..."])




##################opening relevant files##########################################################


try:
    # manifest = "D:\FlexNetCodeInsight/tomcat/temp\palamida_update/manifest.txt"
    manifest = installpath +  "/tomcat/temp/palamida_update/manifest.txt"
    manifestfile = open(manifest, "r")
    lines_manifest = manifestfile.readlines()
    for line in lines_manifest:
        if "timestamp" in line:
            details["Manifest"] = line[-13:]
except IOError:
    print("Manifest Log file not accessible")
    details["Manifest"] = "unknown"
try:
    # updatelog = "D:\FlexNetCodeInsight/logs/core.update.log"
    updatelog = installpath + "/logs/core.update.log"
    coreUpdate = open(updatelog, "r")
    lines_coreUpdate = coreUpdate.readlines()
except IOError:
    print("core.update Log file not accessible")



details["Build Number"] = bn

details["Host"]= socket.gethostname()


if(sendtoinflux == 1):
    #print('Is_GA={0},Release={1} Build={2},ManifestTimeStamp={3},PDL_LICENSE={4},PDL_FORGE={5},PDL_COMPONENT={6},PDL_COMPONENT_VERSION={7},PDL_COMPONENT_LICENSE={8},PDL_VULNERABILITY_REGISTRY={9},PDL_VULNERABILITY={10},PDL_COMP_VER_VULNERABILITY={11},PDL_COMP_VER_LICENSE={12},PDL_COMP_VER_METADATA={13},PDL_COMP_VER_RELEASE={14},PDL_OBLIGATION_ORGANIZATION={15},PDL_OBLIGATION_PRIORITY={16},PDL_OBLIGATION_TRIGGER_ACTION={17},PDL_OBLIGATION_TYPE={18},PDL_OBLIGATION={19},PDL_LICENSE_OBLIGATION_MAP={20},PDL_LICENSE_PATTERN={21},PDL_AW_GROUPS={22},PDL_AW_FILES={23},PDL_COMPONENT_MAPPING={24},PDL_LICENSE_DETECTION_XML={25},PDL_VULNERABILITY_MAPPING={26},PDL_COMPONENT_CPE_MAP ={27},PDL_CVE_REFERENCES={28},PDL_CWE={29},PDL_VULNERABILITY_CWE_MAP={30},Total Time={31},host={32}'.format(IsGA,release,details["Manifest"],ValuesInSec["PDL_LICENSE"],ValuesInSec["PDL_FORGE"],ValuesInSec["PDL_COMPONENT"],ValuesInSec["PDL_COMPONENT_VERSION"],ValuesInSec["PDL_COMPONENT_LICENSE"],ValuesInSec["PDL_VULNERABILITY_REGISTRY"],ValuesInSec["PDL_VULNERABILITY"],ValuesInSec["PDL_COMP_VER_VULNERABILITY"],ValuesInSec["PDL_COMP_VER_LICENSE"],ValuesInSec["PDL_COMP_VER_METADATA"],ValuesInSec["PDL_COMP_VER_RELEASE"],ValuesInSec["PDL_OBLIGATION_ORGANIZATION"],ValuesInSec["PDL_OBLIGATION_PRIORITY"],ValuesInSec["PDL_OBLIGATION_TRIGGER_ACTION"],ValuesInSec["PDL_OBLIGATION_TYPE"],ValuesInSec["PDL_OBLIGATION"],ValuesInSec["PDL_LICENSE_OBLIGATION_MAP"],ValuesInSec["PDL_LICENSE_PATTERN"],ValuesInSec["PDL_AW_GROUPS"],ValuesInSec["PDL_AW_FILES"],ValuesInSec["PDL_COMPONENT_MAPPING"],ValuesInSec["PDL_LICENSE_DETECTION_XML"],ValuesInSec["PDL_VULNERABILITY_MAPPING"],ValuesInSec["PDL_COMPONENT_CPE_MAP "],ValuesInSec["PDL_CVE_REFERENCES"],ValuesInSec["PDL_CWE"],ValuesInSec["PDL_VULNERABILITY_CWE_MAP"],ValuesInSec["Total Time"],details["Host"]))
    data1 = "{32},Is_GA={0},Release={1},Build={2},ManifestTimeStamp={3} PDL_LICENSE={4},PDL_FORGE={5},PDL_COMPONENT={6},PDL_COMPONENT_VERSION={7},PDL_COMPONENT_LICENSE={8},PDL_VULNERABILITY_REGISTRY={9},PDL_VULNERABILITY={10},PDL_COMP_VER_VULNERABILITY={11},PDL_COMP_VER_LICENSE={12},PDL_COMP_VER_METADATA={13},PDL_COMP_VER_RELEASE={14},PDL_OBLIGATION_ORGANIZATION={15},PDL_OBLIGATION_PRIORITY={16},PDL_OBLIGATION_TRIGGER_ACTION={17},PDL_OBLIGATION_TYPE={18},PDL_OBLIGATION={19},PDL_LICENSE_OBLIGATION_MAP={20},PDL_LICENSE_PATTERN={21},PDL_AW_GROUPS={22},PDL_AW_FILES={23},PDL_COMPONENT_MAPPING={24},PDL_LICENSE_DETECTION_XML={25},PDL_VULNERABILITY_MAPPING={26},PDL_COMPONENT_CPE_MAP={27},PDL_CVE_REFERENCES={28},PDL_CWE={29},PDL_VULNERABILITY_CWE_MAP={30},TotalTime={31}".format(
        IsGA, release, bn, details["Manifest"], ValuesInSec["PDL_LICENSE "], ValuesInSec["PDL_FORGE "],
        ValuesInSec["PDL_COMPONENT "], ValuesInSec["PDL_COMPONENT_VERSION "], ValuesInSec["PDL_COMPONENT_LICENSE "],
        ValuesInSec["PDL_VULNERABILITY_REGISTRY "], ValuesInSec["PDL_VULNERABILITY "],
        ValuesInSec["PDL_COMP_VER_VULNERABILITY "], ValuesInSec["PDL_COMP_VER_LICENSE "],
        ValuesInSec["PDL_COMP_VER_METADATA "], ValuesInSec["PDL_COMP_VER_RELEASE "],
        ValuesInSec["PDL_OBLIGATION_ORGANIZATION "], ValuesInSec["PDL_OBLIGATION_PRIORITY "],
        ValuesInSec["PDL_OBLIGATION_TRIGGER_ACTION "], ValuesInSec["PDL_OBLIGATION_TYPE "],
        ValuesInSec["PDL_OBLIGATION "], ValuesInSec["PDL_LICENSE_OBLIGATION_MAP "], ValuesInSec["PDL_LICENSE_PATTERN "],
        ValuesInSec["PDL_AW_GROUPS "], ValuesInSec["PDL_AW_FILES "], ValuesInSec["PDL_COMPONENT_MAPPING "],
        ValuesInSec["PDL_LICENSE_DETECTION_XML "], ValuesInSec["PDL_VULNERABILITY_MAPPING "],
        ValuesInSec["PDL_COMPONENT_CPE_MAP "], ValuesInSec["PDL_CVE_REFERENCES "], ValuesInSec["PDL_CWE "],
        ValuesInSec["PDL_VULNERABILITY_CWE_MAP "], ValuesInSec["Total Time"],box)

    response = requests.post('http://10.75.115.96:8086/write?db=testv', data=data1)
    if response.status_code==204:
        details["Time Stored in Influx "]="True"

f = open("myfile.txt", "w")
for key, value in details.items():
    print("{:<8}: {:<15} <BR>".format(key, value))
    f.write("{:<8}: {:<15} <BR> ".format(key, value))
for key, value in values.items():
    print("{:<8}: {:<15} ".format(key, value))
    f.write("{:<8}: {:<15} ".format(key, value))

if len(allexceptions)>0:
    f.write("Following exceptions in core.log while PDL was in progress <BR> \n")
    for each in allexceptions:
        f.write(each + "<BR>")


for line in lines_coreUpdate:
    if re.search(exception1,line):
        print("Following exceptions seen in core.update.log : \n")
        f.write("Following exceptions seen in core.update.log : \n")
        print(line)
        f.write(line)
        break;

f.close()


