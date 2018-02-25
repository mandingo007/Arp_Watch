from scapy.all import *
import logging

filename = 'arp_sniff.txt' # The file to write to
logging.basicConfig(filename=filename, level=logging.INFO,
                    format='%(asctime)s:%(message)s') # Setup for the logging

Gw_MAC = 'b8-ee-0e-56-69-38' # Change this with your Gateway MAC address
Gw_IP = '192.168.1.1' # Change this with your Gateway IP address
spoof_count = 0 # Set the check for spoofing

# Print Arp requests and responses
def arp_print(packet):
    global spoof_count
    if packet[ARP].op == 1: # Who-Has request
        request = "Request: {} asks for {}.".format(packet[ARP].psrc, packet[ARP].pdst) # Set up the request
        logging.info("\t{}".format(request)) # Log the request
        # Print the request with the source IP and destination IP
        return request
    elif packet[ARP].op == 2: # Is-At response
        response = "Response: {} is at {}.".format(packet[ARP].hwsrc, packet[ARP].psrc) # Set up the response
        # Check the MAC of the gw and the IP of the gw
        if packet[ARP].hwsrc != Gw_MAC and packet[ARP].psrc == Gw_IP:
            spoof_count += 1 # Increase the count for spoofing
            if spoof_count == 10:
                spoof_count = 0 # Reset the spoofing alert
            if spoof_count >= 3: # Check for the spoofing count
                logging.critical("\t[#]--------[ ALERT ]--------[#] : {}".format(response))
        else:
            logging.info("\t{}".format(response)) # Log the response
        # Print the response with source MAC and source IP
        return response






if __name__ == '__main__':
    sniff(filter='arp', prn=arp_print, store=0) # Start sniffing
