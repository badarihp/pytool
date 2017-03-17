#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - November 2012
# Version 0.3.1, Last change on Nov 10, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# HSS Simulator (multiple clients) build upon libDiameter 
# interrupt the program with Ctrl-C

#Next two lines include parent directory where libDiameter is located
import sys
sys.path.append("..")
# Remove them if everything is in the same dir

import socket
import select
import logging
from libDiameter import *
from libScef import *

SKIP=0
def set_env_variables():
    global DICTIONARY_FILE
    global USER_NAME
    global HOST
    global PORT
    global ORIGIN_HOST
    global ORIGIN_REALM
    global MSISDN
    
    DICTIONARY_FILE=getDictionaryFile()
    USER_NAME=getImsi_s6t()
    HOST=getHostIP_s6t()
    PORT=int(getPortNum_s6t())
    ORIGIN_HOST=getOriginHost_s6t()
    ORIGIN_REALM=getOriginRealm_s6t()
    MSISDN=getMsisdn_s6t()

def handle_HSS(conn):
    global sock_list
    # conn is the TCP socket connected to the client
    dbg="Connection:",conn.getpeername(),'to',conn.getsockname()
    print dbg
    #get input ,wait if no data
    data=conn.recv(BUFFER_SIZE)
    #suspect more data (try to get it all without stopping if no data)
    if (len(data)==BUFFER_SIZE):
        while 1:
            try:
                data+=self.request.recv(BUFFER_SIZE, socket.MSG_DONTWAIT)
            except:
                #error means no more data
                break
    if (data != ""): 
        #processing input
        ret=process_request(data.encode("hex")) 
        if ret==ERROR:
            print "Error responding"
        else:
            if ret==SKIP:
                print "Skipping response"
            else:
                conn.send(ret.decode("hex"))    
    else:
        #no data found exit loop (posible closed socket)        
        # remove it from sock_list
        sock_list.remove(conn)
        conn.close()

def handle_CMD(srv):
    conn,address=srv.accept()
    #get input ,wait if no data
    data=conn.recv(BUFFER_SIZE)
    #suspect more data (try to get it all without stopping if no data)
    if (len(data)==BUFFER_SIZE):
        while 1:
            try:
                data+=self.request.recv(BUFFER_SIZE, socket.MSG_DONTWAIT)
            except:
                #error means no more data
                break
    if (data != ""): 
        #processing input
        ret=process_CMD(data.encode("hex")) 
        if ret==ERROR:
            print "Quitting"
            conn.close()
            return ERROR
        else:
            print "Sending command"
            sock_list[-1].send(ret.decode("hex"))    
    conn.close()
    return 
    
def create_CEA(H):
    print "="*30
    print "Received CER"
    print "="*30
    CER_avps=splitMsgAVPs(H.msg)
    print "Hop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in CER_avps:
       print "Decoded AVP",decodeAVP(avp)

    global DEST_REALM
    DEST_REALM=findAVP("Origin-Realm",CER_avps)
    # Let's build Capabilites-Exchange Answer
    CEA_avps=[]
    CEA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CEA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CEA_avps.append(encodeAVP("Vendor-Id", 11))
    CEA_avps.append(encodeAVP("Product-Name", "HSSsim"))
    CEA_avps.append(encodeAVP("Auth-Application-Id", APPLICATION_ID))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 10415))
    CEA_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
        encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),
        encodeAVP("Auth-Application-Id",APPLICATION_ID)]))
    CEA_avps.append(encodeAVP("Result-Code", 2001))   #DIAMETER_SUCCESS 2001
    # Create message header (empty)
    CEA=HDRItem()
    # Set command code
    CEA.cmd=H.cmd
    # Set Application-id
    CEA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    CEA.HopByHop=H.HopByHop
    CEA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(CEA,CEA_avps)
    # ret now contains CEA Response as hex string
    print "="*30
    print "Sending CEA"
    print "="*30
    print "Hop-by-Hop=",CEA.HopByHop,"End-to-End=",CEA.EndToEnd,"ApplicationId=",CEA.appId
    for avp in CEA_avps:
       print "Encoded AVP",decodeAVP(avp)
    return ret

def create_DWA(H):
    print "="*30
    print "Received DWR"
    print "="*30
    DWR_avps=splitMsgAVPs(H.msg)
    print "Hop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in DWR_avps:
       print "Decoded AVP",decodeAVP(avp)

    # Let's build Diameter-WatchdogAnswer 
    DWA_avps=[]
    DWA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    DWA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    DWA_avps.append(encodeAVP("Result-Code", 2001)) #DIAMETER_SUCCESS 2001
    # Create message header (empty)
    DWA=HDRItem()
    # Set command code
    DWA.cmd=H.cmd
    # Set Application-id
    DWA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    DWA.HopByHop=H.HopByHop
    DWA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(DWA,DWA_avps)
    # ret now contains DWA Response as hex string
    print "="*30
    print "Sending DWA"
    print "="*30
    print "Hop-by-Hop=",DWA.HopByHop,"End-to-End=",DWA.EndToEnd,"ApplicationId=",DWA.appId
    for avp in DWA_avps:
       print "Encoded AVP",decodeAVP(avp)
    return ret

def create_NIA(H):
    print "\n"
    print "="*30
    print "Received NIR"
    print "="*30
    NIR_avps=splitMsgAVPs(H.msg)
    print "Hop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in NIR_avps:
       print "Decoded AVP",decodeAVP(avp)
    sesID=findAVP("Session-Id",NIR_avps)
    niddAuth = findAVP("NIDD-Authorization-Request",NIR_avps)
    avpName,servSelection = niddAuth[0]
    extID = getExtId_s6t(servSelection)
    NIA_avps=[]
    NIA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    NIA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    NIA_avps.append(encodeAVP("Session-Id", sesID))
    # Grouped AVPs are encoded like this
    NIA_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
        encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),
        encodeAVP("Auth-Application-Id",H.appId)]))
    NIA_avps.append(encodeAVP("Auth-Session-State", 1)) # 1 - NO_STATE_MAINTAINED
    NIA_avps.append(encodeAVP("Result-Code", 2001))   #DIAMETER_SUCCESS 2001
    NIA_avps.append(encodeAVP("NIDD-Authorization-Response",[
        encodeAVP("User-Name", USER_NAME),
        encodeAVP("3GPP-MSISDN", MSISDN),
        encodeAVP("External-Identifier", extID)]))
    # Create message header (empty)
    NIA=HDRItem()
    # Set command code
    NIA.cmd=H.cmd
    # Set Application-id
    NIA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    NIA.HopByHop=H.HopByHop
    NIA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(NIA,NIA_avps)
    # ret now contains SAA Response as hex string
    print "="*30
    print "Sending NIA"
    print "="*30
    print "Hop-by-Hop=",NIA.HopByHop,"End-to-End=",NIA.EndToEnd,"ApplicationId=",NIA.appId
    for avp in NIA_avps:
       print "Encoded AVP",decodeAVP(avp)
    return ret    
    
def appendToCMD(H):
    # We need to append Host&Realm to message
    CMD_avps=splitMsgAVPs(H.msg)
    CMD_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CMD_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CMD_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    ret=createRes(H,CMD_avps)
    dbg="Appended ",ret
    print dbg
    return ret

def process_CMD(rawdata):
    dbg="Processing CMD",rawdata
    print dbg
    if rawdata[:2]=="01":
        #Diammeter command
        print "Processing diameter request"
        H=HDRItem()
        stripHdr(H,rawdata)
        return appendToCMD(H)
    else:
        return ERROR

def process_request(rawdata):
    H=HDRItem()
    stripHdr(H,rawdata)
    dbg="Processing",dictCOMMANDcode2name(H.flags,H.cmd)
    print dbg
    if H.flags & DIAMETER_HDR_REQUEST==0:
        # If Answer no need to do anything
        # Messages HSS->AAA are send with external put_*.py script
        return SKIP
    if H.cmd==257:  # Capabilities-Exchange
        return create_CEA(H)
    if H.cmd==280:  # Device-Watchdog
        return create_DWA(H)
    if H.cmd==8388726:  # Server-Assignment
        return create_NIA(H)
    return create_UTC(H,"Unknown command code")

def Quit():
    for conn in sock_list:
        conn.close()
    sys.exit(0)
    
if __name__ == "__main__":

    if(len(sys.argv) < 2):
        print "Config file is mandatory. Usage : HSS_Simulator.py -c <file_name>"
        sys.exit(0)
    arg_1 = sys.argv[1];
    if(arg_1 == '-c'):
        config_file = sys.argv[2]
    else:
        print "Invalid argument. Usage : HSS_Simulator.py -c <file_name>"
        sys.exit(0)
    try:
        fd = open(config_file,'r')
    except IOError:
        print "Can't open config file: " + config_file
        sys.exit(0)
    load_config(fd)
    set_env_variables()
    # Define command port to trigger PPR/RTR and other HSS initiated commands
    CMD_PORT = 3870
    
    APPLICATION_ID = 16777345
    LoadDictionary(DICTIONARY_FILE)

    BUFFER_SIZE=1024    
    MAX_CLIENTS=3
    sock_list=[]

    # Create the server, binding to HOST:PORT
    HSS_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # fix "Address already in use" error upon restart
    HSS_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    HSS_server.bind((HOST, PORT))
    HSS_server.listen(MAX_CLIENTS)
    sock_list.append(HSS_server)

    # Create the server, binding to HOST:CMD_PORT
    CMD_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # fix "Address already in use" error upon restart
    CMD_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    CMD_server.bind((HOST, CMD_PORT))  
    CMD_server.listen(MAX_CLIENTS)
    sock_list.append(CMD_server)
    print "HSS Server started. Listening on port: " + str(PORT)
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    while True:
        try:
            read, write, error = select.select(sock_list,[],[],1)
        except:
            break
        for r in read:
            print "="*30
            print "Incoming data"
            # First handle command connection to CMD_server
            if r==CMD_server:
                if handle_CMD(CMD_server)==ERROR:
                    print "Exiting"
                    Quit()
            else:
                # Is it new or existing connection
                if r==HSS_server:
                    # New connections: accept on new socket
                    conn,addr=HSS_server.accept()
                    sock_list.append(conn)
                    if handle_HSS(conn)==ERROR:
                        Quit()
                else:
                    if handle_HSS(r)==ERROR:
                        Quit()
    Quit()

######################################################        
# History
