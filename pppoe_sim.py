# -*- coding: utf-8 -*-
from scapy.all import *
from scapy.layers.ppp import *
import os
import platform
import threading

interface="以太网"
ac_name = "MYSERVER"
service_name = ""
magic_number = 0xDEADBEEF
username = passwd = host_uniq = session_id = ac_cookie = mac_router = mac_server = eth_discovery = eth_session = None
ident = 0
iface = None
e = threading.Event()

End_Of_List = 0x0000
Service_Name = 0x0101
AC_Name = 0x0102
Host_Uniq = 0x0103
AC_Cookie = 0x0104
Vendor_Specific = 0x0105
Relay_Session_Id = 0x0110
Service_Name_Error = 0x0201
AC_System_Error = 0x0202
Generic_Error = 0x0203

PADI = 0x09
PADO = 0x07
PADR = 0x19
PADS = 0x65
PADT = 0xa7

LCP = 0xc021
PAP = 0xc023
CHAP = 0xc223
IPCP = 0x8021
IPV6CP = 0x8057
PPPoE_Discovery = 0x8863
PPPoE_Session = 0x8864

Configure_Request = 1
Configure_Ack = 2
Authenticate_Ack = 2
Configure_Nak = 3
Configure_Reject = 4
Terminate_Request = 5
Terminate_Ack = 6
Code_Reject = 7
Protocol_Reject = 8
Echo_Request = 9
Echo_Reply = 10
Discard_Request = 11


def packet_callback(pkt):
    global host_uniq, session_id, ident, ac_cookie, mac_router, mac_server, eth_discovery, eth_session, iface, username, passwd
    mac_router = pkt[Ether].src
    eth_discovery = Ether(src=mac_server, dst=mac_router, type=PPPoE_Discovery)
    eth_session = Ether(src=mac_server, dst=mac_router, type=PPPoE_Session)
    
    if pkt.haslayer(PPPoED):
        if pkt[PPPoED].code == PADI:
            # print("检测到PPPOE数据包,请返回解锁工具窗口按y继续")
            print("6.检测到PPPoE数据包，30秒内出结果...")
            print("\n\n=========================解析=======================")
            print("Discovery:")
            session_id = pkt[PPPoED].fields['sessionid']
            ac_cookie = os.urandom(20)
            for tag in pkt[PPPoED][PPPoED_Tags].tag_list:
                if tag.tag_type == Host_Uniq:
                    host_uniq = tag.tag_value
            print("\t1.PADI Client->Server %s->%s" % (pkt[Ether].src, pkt[Ether].dst))
            print("\t\tHost_uniq:", list(host_uniq))
            sendp(eth_discovery /
                  PPPoED(code=PADO, sessionid=0) /
                  PPPoETag(tag_type=Service_Name, tag_value=service_name) /
                  PPPoETag(tag_type=AC_Name, tag_value=ac_name) /
                  PPPoETag(tag_type=AC_Cookie, tag_value=ac_cookie) /
                  PPPoETag(tag_type=Host_Uniq, tag_value=host_uniq), iface=iface)
            print("\t2.PADO Server->Client %s->%s" % (eth_discovery[Ether].src, eth_discovery[Ether].dst))
            print("\t\tAC_Name:", ac_name)
            print("\t\tAC_Cookie:", list(ac_cookie))
            print("\t\tHost_uniq:", list(host_uniq))
        elif pkt[PPPoED].code == PADR:
            print("\t3.PADR Client->Server %s->%s" % (pkt[Ether].src, pkt[Ether].dst))
            for tag in pkt[PPPoED][PPPoED_Tags].tag_list:
                if tag.tag_type == Host_Uniq:
                    host_uniq = tag.tag_value
                elif tag.tag_type == AC_Cookie:
                    ac_cookie = tag.tag_value
            print("\t\tAC_Cookie:", list(ac_cookie))
            print("\t\tHost_uniq:", list(host_uniq))
            session_id = os.urandom(2)[0]
            sendp(eth_discovery /
                  PPPoED(code=PADS, sessionid=session_id) /
                  PPPoETag(tag_type=Service_Name, tag_value=service_name) /
                  PPPoETag(tag_type=Host_Uniq, tag_value=host_uniq), iface=iface)
            print("\t4.PADS Server->Client %s->%s" % (eth_discovery[Ether].src, eth_discovery[Ether].dst))
            print("\t\tSession_id:", session_id)
            print("\t\tHost_uniq:", list(host_uniq))

            sendp(eth_session /
                  PPPoE(sessionid=session_id) /
                  PPP(proto=LCP) /
                  PPP_LCP(code=Configure_Request, id=ident + 1, data=(Raw(PPP_LCP_MRU_Option(max_recv_unit=1492)) /
                                                                      Raw(PPP_LCP_Auth_Protocol_Option(
                                                                       auth_protocol=PAP)) /
                                                                      Raw(PPP_LCP_Magic_Number_Option(
                                                                       magic_number=magic_number)))), iface=iface)
            print("\n\nLink Control Protocol:")
            print("\tConfiguration Request Server->Client %s->%s" % (eth_session[Ether].src, eth_session[Ether].dst))
            print("\t\tSession_id:", session_id)
            print("\t\tId:", ident)
            print("\t\tProtocol:", PAP)
            print("\t\tMax_Receive_unit:", 1492)
            print("\t\tMagic_number:", magic_number)


    elif pkt.haslayer(PPPoE) and pkt.haslayer(PPP):
        if pkt[PPPoE].sessionid != 0:
            session_id = pkt[PPPoE].sessionid
        if pkt.haslayer(PPP_LCP_Configure):
            ppp_lcp = pkt[PPP_LCP_Configure]
            if ppp_lcp.code == Configure_Request:
                ident = ppp_lcp.id
                print("\tConfiguration Request Client->Server %s->%s" % (pkt[Ether].src, pkt[Ether].dst))
                print("\t\tSession_id:", pkt[PPPoE].sessionid)
                print("\t\tId:", ident)
                print("\t\tProtocol:", "[Set MRU]" if not ppp_lcp.haslayer(PPP_LCP_Auth_Protocol_Option) else ppp_lcp[PPP_LCP_Auth_Protocol_Option].auth_protocol)
                print("\t\tMax_Receive_unit:", "[Set Protocol]" if not ppp_lcp.haslayer(PPP_LCP_MRU_Option) else ppp_lcp[PPP_LCP_MRU_Option].max_recv_unit)
                print("\t\tMagic_number:", ppp_lcp[PPP_LCP_Magic_Number_Option].magic_number)
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=LCP) /
                      PPP_LCP(code=Configure_Ack, id=ident, data=(Raw(ppp_lcp[PPP_LCP_MRU_Option]) /
                                                                  Raw(ppp_lcp[PPP_LCP_Magic_Number_Option]))), iface=iface)
                print("\tConfiguration Request Server->Client %s->%s" % (eth_session[Ether].src, eth_session[Ether].dst))
                print("\t\tSession_id:", session_id)
                print("\t\tId:", ident)
                print("\t\tProtocol:", "[Set MRU]" if not ppp_lcp.haslayer(PPP_LCP_Auth_Protocol_Option) else ppp_lcp[PPP_LCP_Auth_Protocol_Option].auth_protocol)
                print("\t\tMax_Receive_unit:", "[Set Protocol]" if not ppp_lcp.haslayer(PPP_LCP_MRU_Option) else ppp_lcp[PPP_LCP_MRU_Option].max_recv_unit)
                print("\t\tMagic_number:", ppp_lcp[PPP_LCP_Magic_Number_Option].magic_number)

            
            elif pkt[PPP_LCP_Configure].code == Configure_Ack:
                print("\tConfiguration Ack Client->Server %s->%s" % (pkt[Ether].src, pkt[Ether].dst))
                print("\t\tSession_id:", pkt[PPPoE].sessionid)
                print("\t\tId:", ppp_lcp.id)
                print("\t\tProtocol:", "[Set MRU]" if not ppp_lcp.haslayer(PPP_LCP_Auth_Protocol_Option) else ppp_lcp[PPP_LCP_Auth_Protocol_Option].auth_protocol)
                print("\t\tMax_Receive_unit:", "[Set Protocol]" if not ppp_lcp.haslayer(PPP_LCP_MRU_Option) else ppp_lcp[PPP_LCP_MRU_Option].max_recv_unit)
                print("\t\tMagic_number:", ppp_lcp[PPP_LCP_Magic_Number_Option].magic_number)
                
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=LCP) /
                      PPP_LCP_Echo(code=Echo_Request, id=ident + 1, magic_number=magic_number), iface=iface)
                print("\tEcho Request Server->Client %s->%s" % (eth_session[Ether].src, eth_session[Ether].dst))
                print("\t\tSession_id:", session_id)
                print("\t\tId:", ident + 1)
                print("\t\tMagic_number:", magic_number)

        elif pkt.haslayer(PPP_LCP_Echo):
            ppp_lcp_echo = pkt[PPP_LCP_Echo]
            if pkt[PPP_LCP_Echo].code == Echo_Request:
                ident = pkt[PPP_LCP_Echo].id
                print("\tEcho Request Server Client->Server %s->%s" % (pkt[Ether].src, pkt[Ether].dst))
                print("Server->Client   |   Echo Reply")
                print("\t\tSession_id:", pkt[PPPoE].session_id)
                print("\t\tId:", ident)
                print("\t\tProtocol:", ppp_lcp_echo[PPP_LCP_Auth_Protocol_Option].auth_protocol)
                print("\t\tMax_Receive_unit:", ppp_lcp_echo[PPP_LCP_MRU_Option].max_recv_unit)
                print("\t\tMagic_number:", ppp_lcp_echo[PPP_LCP_Magic_Number_Option].magic_number)
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=LCP) /
                      PPP_LCP_Echo(code=Echo_Reply, id=ident, magic_number=magic_number), iface=iface)
                print("\tEcho Request Server Server->Client %s->%s" % (eth_session[Ether].src, eth_session[Ether].dst))

        elif pkt.haslayer(PPP_PAP_Request):
            ppp_pap = pkt[PPP_PAP_Request]
            ident = ppp_pap.id
            print("\n\nPassword Authentication Protocol Request:")
            print("\tEcho Authentication Request Client->Server %s->%s" % (pkt[Ether].src, pkt[Ether].dst))
            print("\t\tId:", ident)
            print("\t\tUser_Name:", ppp_pap.username)
            print("\t\tPasswd:", ppp_pap.password)
            username = ppp_pap.username.decode("utf-8")
            passwd = ppp_pap.password.decode("utf-8")
            e.set()

            print("\tAuthenticate Ack Server->Client")
            sendp(eth_session /
                  PPPoE(sessionid=session_id) /
                  PPP(proto=PAP) /
                  PPP_PAP_Response(code=Authenticate_Ack, id=ident, message="Login ok"), iface=iface)
            print("\t Configuration Request (IP) Server->Client")
            sendp(eth_session /
                  PPPoE(sessionid=session_id) /
                  PPP(proto=IPCP) /
                  PPP_IPCP(code=Configure_Request, id=ident + 1, options=PPP_IPCP_Option_IPAddress(data="10.15.0.8")), iface=iface)
        elif pkt.haslayer(PPP_IPCP):
            ident = pkt[PPP_IPCP].id
            if pkt[PPP_IPCP].options[0].data == "0.0.0.0":
                options = [PPP_IPCP_Option_IPAddress(data="10.16.0.9"),
                           PPP_IPCP_Option_DNS1(data="114.114.114.114"),
                           PPP_IPCP_Option_DNS2(data="114.114.114.114")]
                print("Configuration Request (invalid) Client->Server")
                print("Configuration Nak Server->Client")
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=IPCP) /
                      PPP_IPCP(code=Configure_Nak, id=ident, options=options), iface=iface)
            else:
                print("Configuration Request (valid) Client->Server")
                print("Configuration Ack Server->Client")
                sendp(eth_session /
                      PPPoE(sessionid=session_id) /
                      PPP(proto=IPCP) /
                      PPP_IPCP(code=Configure_Ack, id=ident, options=pkt[PPP_IPCP].options), iface=iface)
        if pkt[PPP].proto == IPV6CP:
            print("Configuration Request IPV6CP Client->Server")
            print("Protocol Reject IPV6CP Server->Client")
            sendp(eth_session /
                  PPPoE(sessionid=session_id) /
                  PPP(proto=LCP) /
                  PPP_LCP_Protocol_Reject(code=Protocol_Reject, id=ident + 1, rejected_protocol=IPV6CP,
                                          rejected_information=pkt[PPP].payload), iface=iface)


def terminateConnection():
    print("Terminate Connection Server->Client")
    sendp(eth_session /
          PPPoE(sessionid=session_id) /
          PPP(proto=LCP) /
          PPP_LCP_Terminate(), iface=iface)


def isNotOutgoing(pkt):
    if pkt.haslayer(Ether):
        return pkt[Ether].src != mac_server
    return False


if __name__ == '__main__':
    conf.verb = 0  # Suppress Scapy output
    print("\n\n=========================说明=======================")
    print("0.Windows系统请先安装WinPcap_4_1_3.exe或npcap-0.9991.exe")
    print("  Linux系统大佬应该自己知道要配好python3.6.8和scapy包等")
    i = int(input("1.你手边有几根网线(最好有2根，成功率高)? 请输入数量: "))
    if i > 1:
        print("2.用一根网线连接路由器上的wan口到任意一个lan口")
        print("  用另一根网线连接路由器剩下的任意一个lan口到电脑的网口")
    elif i == 1:
        print("2.用网线连接路由器wan口到电脑的网口")
    else:
        print("至少要有一根网线")
        if platform.system() == 'Windows':
            os.system("pause")
            exit(0)
    print("3.给路由器通上电源")
    interface = input("4.输入电脑上连路由器的网络适配器(WIndows)/网卡(Linux)名称: ")
    try:
        iface = IFACES.dev_from_pcapname(pcapname(interface)) if interface else conf.iface # Set default interface
        mac_server = get_if_hwaddr(iface)
    except:
        print("信息错误")
        print(show_interfaces())
        index = input("重新选择，请输入网卡INDEX(编号): ")
        iface = IFACES.dev_from_index(index)

    mac_server = get_if_hwaddr(iface)
    ipaddr = get_if_addr(iface)
    print("  电脑ip:", ipaddr, "电脑mac地址:", mac_server)

    print("5.等待路由器发起PPPoE，一般2分钟内，长时间没反应按CTRL+C结束")
    sniff(prn=packet_callback, iface=iface, filter="pppoed or pppoes", lfilter=isNotOutgoing, stop_filter=lambda p: e.is_set())
    print("\n\n=========================结果=======================")
    if username is not None:
        print("  账号:", username)
    else:
        print("  账号为空或获取失败，请尝试从第1步开始")
    if passwd is not None:
        print("  密码:", passwd)
    else:
        print("  密码为空或获取失败，请尝试从第1步开始")

    if platform.system() == 'Windows':
        os.system("pause")