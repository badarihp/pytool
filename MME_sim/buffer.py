#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3, Last change on Oct 30, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

import datetime
import sys
import socket

#Next line is to include parent directory in PATH where libraries are
sys.path.append("..")
# Remove it normally

from libDiameter import *
from libScef import *

def set_env_variables():
    global DICTIONARY_FILE
    global USER_NAME
    global HOST
    global PORT
    global ORIGIN_HOST
    global ORIGIN_REALM
    global count 
    
    count = 0
    DICTIONARY_FILE=getDictionaryFile()
    USER_NAME=getImsi_t6a()
    HOST=getHostIP_t6a()
    PORT=int(getPortNum_t6a())
    ORIGIN_HOST=getOriginHost_t6a()
    ORIGIN_REALM=getOriginRealm_t6a()

def create_CER():
    # Let's build CER
    CER_avps=[]
    CER_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CER_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CER_avps.append(encodeAVP("Vendor-Id", dictVENDORid2code('TGPP')))
    CER_avps.append(encodeAVP("Origin-State-Id", ORIGIN_ID))
    CER_avps.append(encodeAVP("Supported-Vendor-Id", dictVENDORid2code('TGPP')))
    CER_avps.append(encodeAVP("Auth-Application-Id", APPLICATION_ID))
    CER_avps.append(encodeAVP("Vendor-Specific-Application-Id",[encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),encodeAVP("Auth-Application-Id",APPLICATION_ID)]))

    # Create message header (empty)
    CER=HDRItem()
    # Set command code
    CER.cmd=dictCOMMANDname2code("Capabilities-Exchange")
    # Set Hop-by-Hop and End-to-End
    initializeHops(CER)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(CER,CER_avps)
    # msg now contains CER Request as hex string
    return msg

def create_CMR(flag):
    # Let's build CMR 
    REQ_avps=[]
    REQ_avps.append(encodeAVP('Session-Id', SESSION_ID))
    REQ_avps.append(encodeAVP("User-Identifier", [encodeAVP("User-Name",USER_NAME)] ) )
    if(flag):
        REQ_avps.append(encodeAVP ("Service-Selection", getSecServiceSelection_t6a()))
        REQ_avps.append(encodeAVP('Bearer-Identifier', getSecBearerId_t6a()))
    else:
        REQ_avps.append(encodeAVP ("Service-Selection", getServiceSelection_t6a()))
        REQ_avps.append(encodeAVP('Bearer-Identifier', getBearerId_t6a()))
    REQ_avps.append(encodeAVP('Connection-Action', 0))
    REQ_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    REQ_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    REQ_avps.append(encodeAVP("Destination-Host", DEST_HOST))
    REQ_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    REQ_avps.append(encodeAVP('Auth-Session-State', 1))


    # Create message header (empty)
    REQ=HDRItem()
    setFlags(REQ, DIAMETER_HDR_REQUEST | DIAMETER_HDR_PROXIABLE)
    # Set command code
    REQ.cmd=dictCOMMANDname2code("3GPP-Connection-Management")
    # Set Application-Id
    REQ.appId=APPLICATION_ID
    # Set Hop-by-Hop and End-to-End
    initializeHops(REQ)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    H=HDRItem()
    stripHdr(H, msg)
    print "\nSending CMR for connection establishment:"
    avps=splitMsgAVPs(H.msg)
    print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in avps:
       print "Encoded AVP",decodeAVP(avp)
    # msg now contains CMR Request as hex string
    return msg

def create_CMR_update():
    # Let's build CMR 
    REQ_avps=[]
    REQ_avps.append(encodeAVP('Session-Id', SESSION_ID))
    REQ_avps.append(encodeAVP("User-Identifier", [encodeAVP("User-Name",USER_NAME)] ) )
    REQ_avps.append(encodeAVP ("Service-Selection", getServiceSelection_t6a()))
    REQ_avps.append(encodeAVP('Bearer-Identifier', getBearerId_t6a()))
    REQ_avps.append(encodeAVP('Connection-Action', 2))
    REQ_avps.append(encodeAVP('CMR-Flags', 1))
    REQ_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    REQ_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    REQ_avps.append(encodeAVP("Destination-Host", DEST_HOST))
    REQ_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    REQ_avps.append(encodeAVP('Auth-Session-State', 1))


    # Create message header (empty)
    REQ=HDRItem()
    setFlags(REQ, DIAMETER_HDR_REQUEST | DIAMETER_HDR_PROXIABLE)
    # Set command code
    REQ.cmd=dictCOMMANDname2code("3GPP-Connection-Management")
    # Set Application-Id
    REQ.appId=APPLICATION_ID
    # Set Hop-by-Hop and End-to-End
    initializeHops(REQ)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    H=HDRItem()
    stripHdr(H, msg)
    print "\nSending CMR for connection release:"
    avps=splitMsgAVPs(H.msg)
    print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in avps:
       print "Encoded AVP",decodeAVP(avp)
    # msg now contains CMR Request as hex string
    return msg


def create_CMR_release():
    # Let's build CMR 
    REQ_avps=[]
    REQ_avps.append(encodeAVP('Session-Id', SESSION_ID))
    REQ_avps.append(encodeAVP("User-Identifier", [encodeAVP("User-Name",USER_NAME)] ) )
    REQ_avps.append(encodeAVP ("Service-Selection", getServiceSelection_t6a()))
    REQ_avps.append(encodeAVP('Bearer-Identifier', getBearerId_t6a()))
    REQ_avps.append(encodeAVP('Connection-Action', 1))
    REQ_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    REQ_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    REQ_avps.append(encodeAVP("Destination-Host", DEST_HOST))
    REQ_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    REQ_avps.append(encodeAVP('Auth-Session-State', 1))


    # Create message header (empty)
    REQ=HDRItem()
    setFlags(REQ, DIAMETER_HDR_REQUEST | DIAMETER_HDR_PROXIABLE)
    # Set command code
    REQ.cmd=dictCOMMANDname2code("3GPP-Connection-Management")
    # Set Application-Id
    REQ.appId=APPLICATION_ID
    # Set Hop-by-Hop and End-to-End
    initializeHops(REQ)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    H=HDRItem()
    stripHdr(H, msg)
    print "\nSending CMR for connection release:"
    avps=splitMsgAVPs(H.msg)
    print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in avps:
       print "Encoded AVP",decodeAVP(avp)
    # msg now contains CMR Request as hex string
    return msg

def processDWR(received):
    #   print "="*30
    #   print "Received DWR"
    #   print "="*30
    H=HDRItem()
    msg=received.encode('hex')
    stripHdr(H, msg)

    DWR_avps=splitMsgAVPs(H.msg)
    #print "Hop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    #   for avp in DWR_avps:
    #      print "Decoded AVP",decodeAVP(avp)

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
    #   print "="*30
    #   print "Sending DWA"
    #   print "="*30
    #   print "Hop-by-Hop=",DWA.HopByHop,"End-to-End=",DWA.EndToEnd,"ApplicationId=",DWA.appId
    #   for avp in DWA_avps:
    Conn.send(ret.decode("hex"))



def create_ODR():
    # Let's build CMR 
    ODR_REQ_avps=[]
    ODR_REQ_avps.append(encodeAVP('Session-Id',SESSION_ID))
    ODR_REQ_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    ODR_REQ_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    ODR_REQ_avps.append(encodeAVP("Destination-Host", DEST_HOST))
    ODR_REQ_avps.append(encodeAVP("Destination-Realm", DEST_REALM))

    ODR_REQ_avps.append(encodeAVP("User-Identifier", [encodeAVP("User-Name",USER_NAME)] ) )
    ODR_REQ_avps.append(encodeAVP ("Service-Selection", getServiceSelection_t6a()))
    ODR_REQ_avps.append(encodeAVP('Bearer-Identifier', getBearerId_t6a()))
    ODR_REQ_avps.append(encodeAVP('Non-IP-Data', getNonIPData_t6a()))
    ODR_REQ_avps.append(encodeAVP('Auth-Session-State', 1))


    # Create message header (empty)
    ODR_REQ=HDRItem()
    setFlags(ODR_REQ, DIAMETER_HDR_REQUEST | DIAMETER_HDR_PROXIABLE)
    # Set command code
    ODR_REQ.cmd=dictCOMMANDname2code("3GPP-MO-Data")
    # Set Application-Id
    ODR_REQ.appId=APPLICATION_ID
    # Set Hop-by-Hop and End-to-End
    initializeHops(ODR_REQ)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(ODR_REQ,ODR_REQ_avps)
    H=HDRItem()
    stripHdr(H, msg)
    avps=splitMsgAVPs(H.msg)
    print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in avps:
       print "Encoded AVP",decodeAVP(avp)
    # msg now contains ODR Request as hex string
    return msg



def create_TDA(H, resultCode):
    # Let's build Re-Auth Answer   
    # We need Session-Id from Request
    TDR_avps=splitMsgAVPs(H.msg)
    sessID=findAVP("Session-Id",TDR_avps)
    TDA_avps=[]
    TDA_avps.append(encodeAVP('Session-Id', sessID))
    TDA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    TDA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    TDA_avps.append(encodeAVP("Destination-Host", DEST_HOST))
    TDA_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    TDA_avps.append(encodeAVP('Auth-Session-State', 1))

    if (resultCode == 5653):
        TDA_avps.append(encodeAVP("Experimental-Result", [encodeAVP("Experimental-Result-Code", resultCode)] ) )
    #elif (resultCode == 4221) or (resultCode == 2001):
    else:
        TDA_avps.append(encodeAVP('Result-Code', resultCode))

    # Create message header (empty)
    TDA=HDRItem()
    # Set command code
    TDA.cmd=H.cmd
    # Set Application-id
    TDA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    TDA.HopByHop=H.HopByHop
    TDA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    msg=createRes(TDA,TDA_avps)
    H=HDRItem()
    stripHdr(H, msg)
    avps=splitMsgAVPs(H.msg)
    print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in avps:
       print "Encoded AVP",decodeAVP(avp)
    # ret now contains TDA Response as hex string
    return msg     
    
def create_Session_Id():
    #The Session-Id MUST be globally and eternally unique
    #<DiameterIdentity>;<high 32 bits>;<low 32 bits>[;<optional value>]
    now=datetime.datetime.now()
    ret=ORIGIN_HOST+";"
    ret=ret+str(now.year)[2:4]+"%02d"%now.month+"%02d"%now.day
    ret=ret+"%02d"%now.hour+"%02d"%now.minute+";"
    ret=ret+"%02d"%now.second+str(now.microsecond)+";"
    ret=ret+IDENTITY[2:16]
    return ret
 
def processTDR(received, cmd, resultCode):
    global count
    #print "Processing TDR"
    H=HDRItem()
    msg=received.encode('hex')
    stripHdr(H, msg)
    #print "="*30
    print "\nReceived TDR:"
    #print "="*30
    avps=splitMsgAVPs(H.msg)
    #print cmd
    print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    #print "="*30
    for avp in avps:
       print "Decoded AVP",decodeAVP(avp)
    #print "-"*30
    # From TDR we needed Destination-Host and Destination-Realm
    TDR_avps=splitMsgAVPs(H.msg)
    #print Capabilities_avps
    print H
    DEST_HOST=findAVP("Origin-Host",TDR_avps)
    DEST_REALM=findAVP("Origin-Realm",TDR_avps)
    
    print "="*30
    print "\nSending TDA"
    msg=create_TDA(H, resultCode)
    # msg now contains TDA as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))

def receiveNextDiamMsg(Conn):
    #print "Waiting for Next Diam Message:======================>"
    while (1):
        received = Conn.recv(MSG_SIZE)
        H=HDRItem()
        msg=received.encode('hex')
        stripHdr(H, msg)
        rcvd_cmd=dictCOMMANDcode2name(H.flags,H.cmd)
        if rcvd_cmd==ERROR:
            return "null", None, None

        req=rcvd_cmd.split()
        
        print "Received Message is : "+ rcvd_cmd
        #   if(req[0] == "Device-Watchdog"):
        #       print "Ignoring Device-Watchdog Req/Ans"
        #       continue

        if(req[1] == "Request"):
            return "Request", received, req[0]
        elif(req[1] == "Answer"):
            return "Answer", received, req[0]
        else:
            return "null", None, None

def checkForDiamMsg(cmd, rcvd_cmd):
    if(cmd == rcvd_cmd):
        return True
    else:
        return False

def handle_CMR_CMA(flag):
    # Create unique session ID
    global SESSION_ID
    SESSION_ID="CMR_"+create_Session_Id()
    print "="*30
    msg=create_CMR(flag)
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))

    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    msg=received.encode('hex')
    H=HDRItem()
    stripHdr(H, msg)
    print "="*30
    print "\nReceived CMA from SCEF:"
    #print "="*30
    avps=splitMsgAVPs(H.msg)
    cmd=dictCOMMANDcode2name(H.flags,H.cmd)
    if cmd==ERROR:
     print 'Unknown command',H.cmd
    else:
     #print cmd
     print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
     #print "="*30
     for avp in avps:
        print "Decoded AVP",decodeAVP(avp)
    #print "-"*30

if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
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

    LoadDictionary(DICTIONARY_FILE)

    now=datetime.datetime.now()
    ORIGIN_ID=str(now.microsecond)
    IDENTITY=USER_NAME
    # 3GPP  T6a=16777346
    APPLICATION_ID=16777346
    # Let's assume that my Diameter messages will fit into 4k
    MSG_SIZE=4096

    # Connect to server
    Conn=Connect(HOST,PORT)

    ###########################################################
    # CER / CEA
	###########################################################
	# Create unique session ID
    SESSION_ID="CER_"+create_Session_Id()
    msg=create_CER()
    # msg now contains CER Request as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))

    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    CEA=HDRItem()
    stripHdr(CEA,received.encode("hex"))
    # From CEA we needed Destination-Host and Destination-Realm
    Capabilities_avps=splitMsgAVPs(CEA.msg)
    #print Capabilities_avps
    DEST_HOST=findAVP("Origin-Host",Capabilities_avps)
    DEST_REALM=findAVP("Origin-Realm",Capabilities_avps)

    ###########################################################
	#CMR / CMA
    ###########################################################
    handle_CMR_CMA(0)
    #########################
    # Ask for 2nd CMR
    #########################
    print "="*30
    result=raw_input("\nSend Duplicate CMR Y/N:").lower()
    if(result == 'y'):
        handle_CMR_CMA(0)
    print "="*30
    result=raw_input("\nSend Duplicate CMR with differnt APN/Bearer-ID Y/N:").lower()
    if(result == 'y'):
        handle_CMR_CMA(1)
    ###########################################################
    # Initiate ODR / Wait for ODA --> other py script will initiate TDR
    ###########################################################
    #   print "="*30
    #   result=raw_input("\nSend ODR Y/N:").lower()
    #   #print ("Result:"+result)
    #   if(result == 'n'):
    #       print("Exiting")
    #       sys.exit()
    #   print "\nSending ODR:"
    #   SESSION_ID="ODR_"+create_Session_Id()
    #   odr_msg=create_ODR()
    #   logging.debug("+"*30)
    #   # send data
    #   Conn.send(odr_msg.decode("hex"))

    #   mType, received, rcvdMsgType = receiveNextDiamMsg(Conn)
    #   while(received != None):
    #       if(received != None and checkForDiamMsg("3GPP-MO-Data", rcvdMsgType)):
    #           print "="*30
    #           print "\nReceived ODA from SCEF:"
    #           #print "="*30
    #           H=HDRItem()
    #           msg=received.encode('hex')
    #           stripHdr(H, msg)
    #           avps=splitMsgAVPs(H.msg)
    #           cmd=dictCOMMANDcode2name(H.flags,H.cmd)
    #           if cmd==ERROR:
    #            print 'Unknown command',H.cmd
    #           else:
    #            #print cmd
    #            print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    #            #print "="*30
    #            for avp in avps:
    #               print "Decoded AVP",decodeAVP(avp)
    #           #print "-"*30
    #           break
    #       else:
    #           mType, received, rcvdMsgType = receiveNextDiamMsg(Conn)

    ###########################################################
	#TDR / TDA
    ###########################################################
    print "="*30
    print("\nWaiting for TDR from SCEF")
    H=None
    msg=None
    received = None
    resultCode = 2001
    mType, received, rcvdMsgType = receiveNextDiamMsg(Conn)
    print ("rcvdMsgType :" + rcvdMsgType)
    while(received != None):
        if(checkForDiamMsg("3GPP-MT-Data", rcvdMsgType)):
            if ( count < 1 ) :
                resultCode = 2001
                count = count + 1
            else:
               resultCode = 5653
               count = count + 1
               #     resultCode = 5653
            processTDR(received, rcvdMsgType, resultCode)
            if (count > 1):
                break
        elif(checkForDiamMsg("Device-Watchdog", rcvdMsgType)):
            processDWR(received)
        print("Waiting ... ")
        mType, received, rcvdMsgType = receiveNextDiamMsg(Conn)
        print ("rcvdMsgType :" + rcvdMsgType)
        

    ###########################################################
	#CMR-update / CMA
    ###########################################################
    print "="*30
    result=raw_input("\n\nSend CMR with Connection-Update UE Reachable:").lower()
    if (result == 'y'):
        # Create unique session ID
        SESSION_ID="CMR_"+create_Session_Id()
        #msg=create_CMR_release()
        msg=create_CMR_update()
        logging.debug("+"*30)
        # send data
        Conn.send(msg.decode("hex"))

        # Receive response
        received = Conn.recv(MSG_SIZE)
        # split header and AVPs
        msg=received.encode('hex')
        H=HDRItem()
        stripHdr(H, msg)
        print "="*30
        print "\nReceived CMA from SCEF:"
        #print "="*30
        avps=splitMsgAVPs(H.msg)
        cmd=dictCOMMANDcode2name(H.flags,H.cmd)
        if cmd==ERROR:
         print 'Unknown command',H.cmd
        else:
         #print cmd
         print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
         #print "="*30
         for avp in avps:
            print "Decoded AVP",decodeAVP(avp)
        #print "-"*30
        print "="*30

        print("\nWaiting for TDR from SCEF")
        H=None
        msg=None
        received = None
        mType, received, rcvdMsgType = receiveNextDiamMsg(Conn)
        print ("rcvdMsgType :" + rcvdMsgType)
        while(received != None):
            if(checkForDiamMsg("3GPP-MT-Data", rcvdMsgType)):
                processTDR(received, rcvdMsgType, 2001)
            elif(checkForDiamMsg("Device-Watchdog", rcvdMsgType)):
                processDWR(received)
            print("Waiting ... ")
            mType, received, rcvdMsgType = receiveNextDiamMsg(Conn)
            print ("rcvdMsgType :" + rcvdMsgType)




    ###########################################################
	#CMR-release / CMA
    ###########################################################
    print "="*30
    result=raw_input("\n\nSend CMR with connection release Y/N:").lower()
    # Create unique session ID
    SESSION_ID="CMR_"+create_Session_Id()
    msg=create_CMR_release()
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))

    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    msg=received.encode('hex')
    H=HDRItem()
    stripHdr(H, msg)
    print "="*30
    print "\nReceived CMA from SCEF:"
    #print "="*30
    avps=splitMsgAVPs(H.msg)
    cmd=dictCOMMANDcode2name(H.flags,H.cmd)
    if cmd==ERROR:
     print 'Unknown command',H.cmd
    else:
     #print cmd
     print "\nHop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
     #print "="*30
     for avp in avps:
        print "Decoded AVP",decodeAVP(avp)
    #print "-"*30
    print "="*30

    ###########################################################
    # And close the connection
    Conn.close()


