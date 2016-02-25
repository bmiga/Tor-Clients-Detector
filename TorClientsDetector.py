import re
import OpenSSL.crypto
import time

try:
    from scapy.all import *
except ImportError:
    from scapy import *

bind_layers(TCP, SSL, dport=9001)
bind_layers(TCP, SSL, sport=9001)

pattern=re.compile('www\.([abcdefghijklmnopqrstuvwxyz234567]+)\.(net|com)')
c=OpenSSL.crypto


def pkt_callback(pkt):
	if pkt.haslayer(TLSCertificateList):
		x509=c.load_certificate(c.FILETYPE_ASN1,str(pkt[TLSCertificateList].certificates[0].data))
		issuer=x509.get_issuer().get_components()
		subject=x509.get_subject().get_components()
		if x509.get_pubkey().bits()==1024 and len(issuer)==1 and len(subject)==1 and issuer[0][0]=='CN' and subject[0][0]=='CN' and issuer[0][1]!=subject[0][1]:
			if pattern.findall(issuer[0][1]) and pattern.findall(issuer[0][1]):
				print '{0} - {1}:{2} -> {3}:{4}'.format(time.strftime('%c'),pkt[IP].dst,pkt[TCP].dport,pkt[IP].src,pkt[TCP].sport)

print 'Tor Clients Detector'
pkts=sniff(filter='port 443 or port 9001',prn=pkt_callback)

