import sys
import random
import hashlib
import libnum

from p256 import curve,scalar_mult,point_add

msg="Hello"

if (len(sys.argv)>1):
  msg=(sys.argv[1])

# Alice's key pair (dA,QA)
dA = random.randint(0, curve.n-1)
QA = scalar_mult(dA,curve.g)

h=int(hashlib.sha256(msg.encode()).hexdigest(),16)
print(hex(h))
print('-')

k = random.randint(0, curve.n-1)

rpoint = scalar_mult(k,curve.g)

r = rpoint[0] % curve.n

# Bob takes m and (r,s) and checks
inv_k = libnum.invmod(k,curve.n)

s = (inv_k*(h+r*dA)) % curve.n

print (f"Msg: {msg}\n\nAlice's private key={dA}\nAlice's public key={QA}\nk= {k}\n\nr={r}\ns={s}")

print(hex(r))
print(hex(s))
# To check signature

def check(QA, r, s, h):
    inv_s = libnum.invmod(s,curve.n)
    c = inv_s
    u1=(h*c) % curve.n
    u2=(r*c) % curve.n
    P = point_add(scalar_mult(u1,curve.g), scalar_mult(u2,QA))

    res = P[0] % curve.n
    print (f"\nResult r={res}")

    if (res==r):
        print("Signature matches!")

check(QA, r, s, h)


QA = (0x029de200b0a1b23f253a412963517905e08c73277adbcdb07837ec35ff253188, 0xbbc4455556ad16fa2b36edc0a71d901cd2b7ac6474dd5f82a84ab1607a184f70)
r,s = 0x676a148115a3ffbb4aedae6f227d349da39f7fd9d590bca7d0bfa9857b7795c1, 0xbe287b2b82dc6b3abd2c9ee5e6b8918c518b8de20c1bc1b76ba4e4fe0685de3e
h=0x660eb73e0d3fd524e58684c9700790cabbe47739bfdd6a939282ef891b77ed71

print('hehe')
check(QA, r, s, h)
