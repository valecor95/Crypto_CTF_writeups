import gmpy
from Crypto.Util.number import *

N = 86108002918518428671680621078381724386896258624262971787023054651438740237393
e = 65537
p = 286748798713412687878508722355577911069
q = 300290718931931563784555212798489747397
phi = (p - 1) * (q - 1)
d = gmpy.invert(e, phi)
c = open("encrypted.txt", "rb").read()
c = c.hex()
c = int(c, 16)
decrypted = pow(c, d, N)

print("[+] N = "+str(N))
print("[+] e = "+str(e))
print("[+] p = "+str(p))
print("[+] q = "+str(q))
print("[+] phi = "+str(phi))
print("[+] d = "+str(d))
print()
print("[+] Decrypted ciphertext and Found the message m " + str(decrypted))
print("[+] FLAG is ", end=' ')
print(long_to_bytes(decrypted))