# encoding UTF-8
# ############################################################################# 
#= = 文件名称：tcp_server.py 
#= = 文件描述：服务器端
#= = 作    者：indigo 
#= = 编写时间：2016-06-23 21:16:00 
# ############################################################################# 
import socket
import threading

bind_ip   = "0.0.0.0"
bind_port = 5000  
    
class Server():
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
           
    def client_handler(self,client_socket,client_ip,client_port):
              
        while True:
            request = client_socket.recv(1024)
            print "[*] Received(%s,%d):%s " % (client_ip,client_port,request)
            client_socket.send("[*]ACK!")           
            if request == "over":
                client_socket.close()

        
    def work(self):
        #server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server.bind((bind_ip,bind_port))    
        self.server.listen(100)     
        
        print "[*]Start listening..."
        
        try:
            while True:
                client_socket,addr = self.server.accept()
                
                print "[*] Accepted connection from: %s:%d" %(addr[0],addr[1])
                
                client_thread = threading.Thread(target=self.client_handler,args=(client_socket,addr[0],addr[1],))
                client_thread.start() 
        except KeyboardInterrupt:
            print "\n[-]Shutdown the listening!"
            

            
if __name__ == "__main__":
    socket = Server()
    socket.work()
