import sipfullproxy as proxy
import socketserver
import netifaces

if __name__ == "__main__":
    #print(netifaces.interfaces())
    #We get the ip of the wireless interface, different pc's need to use different interface name
    ipaddress = netifaces.ifaddresses('{1F207080-FFAA-4C43-9106-B53397C0F3F7}')[netifaces.AF_INET][0]['addr']
    proxy.HOST = ipaddress
    proxy.logging.basicConfig(filename='phonebook.txt',level=proxy.logging.INFO)
    proxy.recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress,proxy.PORT)
    proxy.topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress,proxy.PORT)
    server = socketserver.UDPServer((proxy.HOST, proxy.PORT), proxy.UDPHandler)
    print("The SIP proxy is running on port: " + str(proxy.PORT))
    print("The proxy is running on ip address: "+ ipaddress)
    server.serve_forever()


