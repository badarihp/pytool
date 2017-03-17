import os
import sys
import socket

common_settings = {}
t6a_settings = {}
s6t_settings = {}

def load_config(fd):
    for line in fd:
        if(line.strip() != ''):
            if (line.strip() == 'COMMON_CONFIG'):
                comm_start = 1
                s6t_start = 0
                t6a_start = 0
            elif (line.strip() == 'T6A_CONFIG'):
                comm_start = 0
                s6t_start = 0
                t6a_start = 1
            elif (line.strip() == 'S6T_CONFIG'):
                comm_start = 0
                s6t_start = 1
                t6a_start = 0
            else:
                temp = line.strip().split(':')
                multiple = 0
                if (len(temp) > 2):
                    multiple = 1
                if(comm_start):
                    common_settings[temp[0].strip()] = temp[1].strip()
                elif(t6a_start):
                    t6a_settings[temp[0].strip()] = temp[1].strip()
                elif(s6t_start):
                    if (multiple):
                        val = {}
                        i =0
                        while ((i+2) < len(temp)):
                            val[temp[i+1].strip()] = temp[i+2].strip()
                            i = i+2
                        s6t_settings[temp[0].strip()] = val
                    else:
                        s6t_settings[temp[0].strip()] = temp[1].strip()
                else:
                    print "Config file is not in proper format"
    fd.close()

# Common Routines
def getDictionaryFile():
    path=common_settings.get('dictionary_path','./')
    dFile=common_settings.get('dictionary_file')

    if os.path.isdir(path):
        filename = os.path.join(path, dFile)
        if(os.path.isfile(filename)):
            return filename
    
    return None

# T6a Related Routines
def getHostIP_t6a():
    ip=t6a_settings.get('host_ip')
    if ip == '' or ip == None:
        HOST=([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        return HOST
    return ip

def getPortNum_t6a():
    port=t6a_settings.get('port')
    if port == '' or port == None:
        port = 3868
    return port

def getOriginHost_t6a():
    oHost=t6a_settings.get('origin_host')
    if oHost == '' or oHost == None:
        oHost = "seagull"
    return oHost

def getOriginRealm_t6a():
    oRealm = t6a_settings.get('origin_realm')
    if oRealm == '' or oRealm == None:
        oRealm = "pcrf.cisc.com"
    return oRealm
 
def getImsi_t6a():
    imsi=t6a_settings.get('imsi')
    if imsi == '' or imsi == None:
        imsi = "262090426000193"
    return imsi

def getBearerId_t6a():
    bearerId=t6a_settings.get('bearer_id')
    if bearerId == '' or bearerId == None:
        bearerId = "0x05"
    return bearerId

def getSecBearerId_t6a():
    bearerId=t6a_settings.get('bearer_id-sec')
    if bearerId == '' or bearerId == None:
        bearerId = "0x06"
    return bearerId

def getServiceSelection_t6a():
    servSelection=t6a_settings.get('apn')
    if servSelection == '' or servSelection == None:
        servSelection = "iot-apn-1"
    return servSelection

def getSecServiceSelection_t6a():
    servSelection=t6a_settings.get('apn-sec')
    if servSelection == '' or servSelection == None:
        servSelection = "iot-apn-2"
    return servSelection

def getNonIPData_t6a():
    data=t6a_settings.get('non_ip_data')
    if data == '' or data == None:
        data = "0x05"
    return data

# S6T Related routines
def getHostIP_s6t():
    ip=s6t_settings.get('host_ip')
    if ip == '' or ip == None:
        HOST=([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        return HOST
    return ip

def getPortNum_s6t():
    port=s6t_settings.get('port')
    if port == '' or port == None:
        port = 3868
    return port

def getOriginHost_s6t():
    oHost=s6t_settings.get('origin_host')
    if oHost == '' or oHost == None:
        oHost = "seagull"
    return oHost

def getOriginRealm_s6t():
    oRealm = s6t_settings.get('origin_realm')
    if oRealm == '' or oRealm == None:
        oRealm = "pcrf.cisc.com"
    return oRealm
 
def getImsi_s6t():
    imsi=s6t_settings.get('imsi')
    if imsi == '' or imsi == None:
        imsi = "262090426000193"
    return imsi

def getMsisdn_s6t():
    msisdn=s6t_settings.get('msisdn')
    if msisdn == '' or msisdn == None:
        msisdn = "1234567890"
    return msisdn

def getExtId_s6t(apn):
    apn_ext_id=s6t_settings.get('apn_ext_id')
    if apn_ext_id == '' or apn_ext_id == None:
        return 'ext-id-1@cisco.com'
    extID = apn_ext_id.get(apn)
    if extID == '' or extID == None:
        return 'ext-id-1@cisco.com'
    return extID