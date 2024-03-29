#!/usr/bin/env python3
from statemachine import StateMachine, State
import pyshark
from enum import Enum
from multiprocessing import Process
import socket
import sys
import os
from datetime import datetime
import time

s1ap_procedures = {17: "s1_setup", 12: "initial_ue_message", 11: "dl_nas", 13: "ul_nas",
        9: "initial_context_setup", 22: "ue_cap_ind", 23: "ue_context_release", 10: "paging", 18: "ue_context_release_request"}

enb_dct = {}
ue_dct = {}

s1ap_CauseRadioNetwork_vals = {0: "unspecified", 1: "tx2relocoverall-expiry", 2: "successful-handover",
        3: "release-due-to-eutran-generated-reason", 4: "handover-cancelled",
        5: "partial-handover", 6: "ho-failure-in-target-EPC-eNB-or-target-system",
        7: "ho-target-not-allowed", 8: "tS1relocoverall-expiry", 9: "tS1relocprep-expiry",
        10: "cell-not-available", 11: "unknown-targetID",
        12: "no-radio-resources-available-in-target-cell", 13: "unknown-mme-ue-s1ap-id",
        14: "unknown-enb-ue-s1ap-id", 15: "unknown-pair-ue-s1ap-id",
        16: "handover-desirable-for-radio-reason", 17: "time-critical-handover",
        18: "resource-optimisation-handover", 19: "reduce-load-in-serving-cell",
        20: "user-inactivity", 21: "radio-connection-with-ue-lost",
        22: "load-balancing-tau-required", 23: "cs-fallback-triggered",
        24: "ue-not-available-for-ps-service", 25: "radio-resources-not-available",
        26: "failure-in-radio-interface-procedure", 27: "invalid-qos-combination",
        28: "interrat-redirection", 29: "interaction-with-other-procedure",
        30: "unknown-E-RAB-ID", 31: "multiple-E-RAB-ID-instances",
        32: "encryption-and-or-integrity-protection-algorithms-not-supported",
        33: "s1-intra-system-handover-triggered", 34: "s1-inter-system-handover-triggered",
        35: "x2-handover-triggered", 36: "redirection-towards-1xRTT",
        37: "not-supported-QCI-value", 38: "invalid-CSG-Id"}

s1ap_Cause_vals = {0: "radioNetwork",
        1: "transport",
        2: "nas",
        3: "protocol",
        4: "misc"}

class S1apProcedureCode(Enum):
    AUTH_REQUEST = 82
    AUTH_RESPONSE = 83
    SEC_MODE_CMD = 93
    SEC_MODE_COMPLETE = 94
    ATTACH_COMPLETE = 67
    DETACH_REQUEST = 69




class EmmFSM(StateMachine):
    Off = State('DE-REGISTERED', initial=True)
    Registered = State('REGISTERED')

    UE_EMM_REGISTERED = Off.to(Registered)
    UE_EMM_DE_REGISTERED = Registered.to(Off)


class EcmFSM(StateMachine):
    Off = State('IDLE', initial=True)
    Active = State('CONNECTED')

    UE_ECM_ACTIVE = Off.to(Active)
    UE_ECM_IDLE = Active.to(Off)


class EnodeB(object):
    def __init__(self, enodeb_name, enb_id, global_enb_id, addr):
        self.enodeb_name = enodeb_name
        self.enb_id = enb_id
        self.global_enb_id = global_enb_id
        self.address = addr


class UECb(object):
    def __init__(self, _imsi, _enb_ue_s1ap_id):
        self.imsi = _imsi
        self.m_tmsi = 0
        self.enb_ue_s1ap_id = _enb_ue_s1ap_id
        self.mme_ue_s1ap_id = 0
        self.emm_state = 0
        self.ecm_state = 0

def timestamp():
    ts = time.time()
    st = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    return st



def s1_setup(pkt):
    global enb_dct
    s1ap_field_names = pkt.s1ap.field_names 
    if "s1setuprequest_element" in s1ap_field_names:
        print("%s [%s] S1 Setup Request" %(timestamp(), pkt.ip.src))
        enb_dct[pkt.s1ap.enodebname] = EnodeB(pkt.s1ap.enodebname, int(pkt.s1ap.enb_id), pkt.s1ap.global_enb_id_element, pkt.ip.src)
    elif "s1setupresponse_element" in s1ap_field_names: 
        print("%s S1 Setup Response" %timestamp())
    else:
        pass


def initial_ue_message(pkt):
    org_list = pkt.s1ap.field_names
    new_list = list(filter(None, org_list))
    if "s_tmsi_element" in new_list:
        print("{8} [{0}] Initial UE Message Cause: {1} MCC: {2} PlmnId: {3} MMEC: {4} cellId: {5} MTMSI: {6} MNC: {7}".format(pkt.s1ap.enb_ue_s1ap_id, pkt.s1ap.rrc_establishment_cause, pkt.s1ap.e212_mcc, pkt.s1ap.plmnidentity, pkt.s1ap.mmec, pkt.s1ap.cellidentity, pkt.s1ap.m_tmsi, pkt.s1ap.e212_mnc, timestamp()))
    else:
        for val in new_list: 
            cmd = 'pkt.s1ap.' + val
            print("{2} {0} = {1}".format(val, eval(cmd), timestamp()))



    
def ul_nas(pkt):
    global ue_dct
    global S1apProcedureCode
    enb_ue = int(pkt.s1ap.enb_ue_s1ap_id)
    mme_ue = int(pkt.s1ap.mme_ue_s1ap_id)
    nas_msg_emm_type = int(pkt.s1ap.nas_eps_nas_msg_emm_type)
    if S1apProcedureCode.DETACH_REQUEST.value == nas_msg_emm_type:
        detach_type = pkt.s1ap.nas_eps_emm_detach_type_ul
        print("%s [%d: %d] Detach Request" % (timestamp(), enb_ue, mme_ue))
        print("%s [UE-NAS-STATE] EMM-DEREGISTERED, ECM-IDLE" %timestamp())
    elif S1apProcedureCode.ATTACH_COMPLETE.value == nas_msg_emm_type:
        eps_bearer_id = pkt.s1ap.nas_eps_bearer_id
        print("%s [%d: %d] Attach Complete " % (timestamp(), enb_ue, mme_ue))
        print("%s [UE-NAS-STATE] EMM-REGISTERED, ECM-CONNECTED" %timestamp())
    elif S1apProcedureCode.AUTH_RESPONSE.value == nas_msg_emm_type:
        print("%s [%d: %d] Authentication Response" % (timestamp(), enb_ue, mme_ue))
    elif S1apProcedureCode.SEC_MODE_COMPLETE.value == nas_msg_emm_type:
        print("%s [%d: %d] Security Mode Complete" % (timestamp(), enb_ue, mme_ue))
    else:
        pass


def dl_nas(pkt):
    enb_ue = int(pkt.s1ap.enb_ue_s1ap_id)
    mme_ue = int(pkt.s1ap.mme_ue_s1ap_id)
    nas_msg_emm_type = int(pkt.s1ap.nas_eps_nas_msg_emm_type)
    if S1apProcedureCode.AUTH_REQUEST.value == nas_msg_emm_type:
        print("%s [%d: %d] Authentication Request" % (timestamp(), enb_ue, mme_ue))
    elif S1apProcedureCode.SEC_MODE_CMD.value == nas_msg_emm_type:
        print("%s [%d: %d] Security Mode Command" % (timestamp(), enb_ue, mme_ue))
    else:
        print("%s EMM message not supported --> "%(timestamp(), hex(nas_msg_emm_type)))


def initial_context_setup(pkt):
    enb_ue = int(pkt.s1ap.enb_ue_s1ap_id)
    mme_ue = int(pkt.s1ap.mme_ue_s1ap_id)
    if 'initialcontextsetuprequest_element' in pkt.s1ap.field_names:
        print("%s [%d: %d] Initial Context Setup Request" % (timestamp(), enb_ue, mme_ue))
    else:
        print("%s [%d: %d] Initial Context Setup Response" % (timestamp(), enb_ue, mme_ue))
        print("%s [UE-NAS-STATE] EMM-REGISTERED, ECM-CONNECTED" %timestamp())


def ue_cap_ind(pkt):
    enb_ue = int(pkt.s1ap.enb_ue_s1ap_id)
    mme_ue = int(pkt.s1ap.mme_ue_s1ap_id)
    print("%s [%d: %d] UE CapabilityInfoIndication, UECapabilityInformation" % (timestamp(), enb_ue, mme_ue))


def ue_context_release(pkt):
    enb_ue = int(pkt.s1ap.enb_ue_s1ap_id)
    mme_ue = int(pkt.s1ap.mme_ue_s1ap_id)
    if 'uecontextreleasecommand_element' in pkt.s1ap.field_names:
        print("%s [%d: %d] UE Context Release Command" % (timestamp(), enb_ue, mme_ue))
    else:
        print("%s [%d: %d] UE Context Release Complete" % (timestamp(), enb_ue, mme_ue))
        print("%s [UE-NAS-STATE] EMM-REGISTERED, ECM-IDLE" %timestamp())

def paging(pkt):
    print("%s Paging Initiated -->" %timestamp())
    print("{8} PlmnID: {0}, UeIdIndex: {1}, MCC: {2}, TAC: {3}, MMEC: {4}, S_TMSI: {5}, M_TMSI: {6}, MNC: {7}, UePagingId: {8}".format(pkt.s1ap.plmnidentity, pkt.s1ap.ueidentityindexvalue, pkt.s1ap.e212_mcc, pkt.s1ap.tac, pkt.s1ap.mmec, pkt.s1ap.s_tmsi_element, pkt.s1ap.m_tmsi, pkt.s1ap.e212_mnc, pkt.s1ap.uepagingid, timestamp()))
    #print(pkt.s1ap.field_names)




def ue_context_release_request(pkt):
    enb_ue = int(pkt.s1ap.enb_ue_s1ap_id)
    mme_ue = int(pkt.s1ap.mme_ue_s1ap_id)
    if "radionetwork" in pkt.s1ap.field_names:
        radioNetwork = int(pkt.s1ap.radionetwork)
        cause = int(pkt.s1ap.cause)
        print("{4} [{0}: {1}] UE Context Release Request --> {2} {3}".format(enb_ue, mme_ue, s1ap_Cause_vals[cause], s1ap_CauseRadioNetwork_vals[radioNetwork], timestamp()))
    else:
        print(pkt.s1ap.field_names)



def capture_packets(intf):
    # capture live packets
    print("Child process started %d" %os.getpid())
    print("Live capture started on interface {0} proto sctp and port 36412".format(intf))
    capture = pyshark.LiveCapture(interface=intf, bpf_filter='sctp port 36412')
    for packet in capture.sniff_continuously():
        chunk_type = int(packet.sctp.chunk_type)
        if chunk_type == 0 or chunk_type == 3:
            try:
                #print("S1AP Procedure Code {0}".format(packet.s1ap.procedurecode))
                procedure_code = int(packet.s1ap.procedurecode)
                try:
                    eval(s1ap_procedures[procedure_code])(packet)
                except KeyError:
                    print("Procedure not supported: %d" %procedure_code)
            except AttributeError:
                #print("No attribute named")
                pass


def print_conversation_header(pkt):
    try:
        # print(pkt.ip.prot)
        if int(pkt.sctp.chunk_type) == 0 or int(pkt.sctp.chunk_type) == 3:
            procedure_code = int(pkt.s1ap.procedurecode)
            eval(s1ap_procedures[procedure_code])(pkt)
    except AttributeError:
        pass


def decode_pcap(file_name):
    cap = pyshark.FileCapture(file_name)
    cap.apply_on_packets(print_conversation_header, timeout=100)


def server():
    global enb_dct
    global ue_dct

    localIP     = "127.0.0.1"
    localPort   = 20001
    bufferSize  = 1024
     

    msgFromServer       = "Hello UDP Client"

    # Create a datagram socket
    UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # Bind to address and ip
    UDPServerSocket.bind((localIP, localPort))

    print("UDP server up and listening")
    # Listen for incoming datagrams
    while(True):
        bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
        message = bytesAddressPair[0]
        address = bytesAddressPair[1]
        clientMsg = "Message from Client:{}".format(message)
        clientIP  = "Client IP Address:{}".format(address)
        print(clientMsg)
        print(clientIP)
        # Sending a reply to client
        data = str(enb_dct)
        bytesToSend = str.encode(data)
        print(bytesToSend)
        UDPServerSocket.sendto(bytesToSend, address)
        data = str(ue_dct)
        bytesToSend = str.encode(data)
        print(bytesToSend)
        UDPServerSocket.sendto(bytesToSend, address)

if __name__ == '__main__':
    
    if len(sys.argv) != 2:
        print("./usuage: program <interface>")
        sys.exit(1)
    else:
        intrf = sys.argv[1]

    p1 = Process(target=capture_packets, args=(intrf,))
    #p1 = Process(target=decode_pcap, args=('attach.pcap',))
    #p2 = Process(target=server, args=(''))
    p1.start()
    #p2.start()
    print("Parent process waiting P1 join() %d" %os.getpid())
    p1.join()
    print("P1 joined...")
    print("Done")

    #p2.join()
    #print("P2 joined...")

