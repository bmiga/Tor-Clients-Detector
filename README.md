# Tor-Clients-Detector

Detektor klientow TOR w sieciach lokalnych. 

Sniffer wyrywajacy polaczenia do serwerow SSL przedstawiajacych sie specyficznymi certyfikatami:
- dlugosc klucza 1024 bitow
- Subject Name != Issuer Name
- Subject Name = "/CN=www.[base32 encoded random int].(net|com)"
- Issuer Name = "/CN=www.[base32 encoded random int].(net|com)"


Wymagania
scapy
pyOpenSSL
