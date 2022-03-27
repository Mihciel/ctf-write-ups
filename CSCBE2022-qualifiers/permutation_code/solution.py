from pwn import *

r = remote("18.202.62.235", 1337)

import functools
import string
alphabet = string.ascii_letters + string.digits + "+/" # Base64 characters
invalph = {}
for i in range(len(alphabet)):
    invalph[alphabet[i]] = i


minX = functools.reduce(lambda a,b: a * b // math.gcd(a,b), range(1, 65 + 1), 1)

def encrypt(m):
    global r
    r.recvuntil(b": ")
    r.send((m +"\n").encode())
    return r.recvline().decode().strip()

from z3 import *
s = Solver()
pindices = [BitVec(f"p{x}", 6) for x in range(64)]
sindices = [BitVec(f"s{x}", 6) for x in range(64)]

for i in range(len(alphabet)):
    for j in range(len(alphabet)):
        if i != j:
            s.add(pindices[i] != pindices[j])
            s.add(sindices[i] != sindices[j])

def add_pc_constraints(s, m, c, pindices, sindices):
    d = Int(f"d{m}")
    s.add(0<=d, d<len(m))
    for i in range(len(m)):
        # add if then else statement as constraint
        s.add(If(d == i, sindices[invalph[c[i]]] == pindices[invalph[m[i]]], sindices[invalph[c[i]]] == (pindices[invalph[m[i]]] ^ sindices[invalph[m[(i+1)%len(m)]]])))
    return d

import random
lengths = [64, 27*2, 25*2, 49, 11*5, 13*5, 17*3, 19*3, 23*2, 29*2, 31*2, 37, 41, 43, 47, 53, 59, 61]
dvars = []
for n in lengths:
    m = "".join(random.choices(alphabet, k=n))
    c = encrypt(m)
    dvars.append(add_pc_constraints(s, m, c, pindices, sindices))

import math
if not s.check():
    print("no SMT model")
    exit()
# the model is wrong about 10% of the time, this will give an error further on in the code
model = s.model()

xmods = [(model[dvars[i]].as_long() - math.floor(math.pow(lengths[i], 1.5))) % lengths[i] for i in range(len(lengths))]

from sympy.ntheory.modular import crt
x = (crt(lengths, xmods)[0] % minX) + minX

Ps = ["="]*64
Ss = ["="]*64
for i in range(len(alphabet)):
    pind = model[pindices[i]].as_long()
    sind = model[sindices[i]].as_long()
    Ps[pind] = alphabet[i]
    Ss[sind] = alphabet[i]

P = "".join(Ps)
S = "".join(Ss)

def decrypt(c, S, P, x):
    n = len(c)
    keySize = len(S)
    inverseP = dict()
    inverseS = dict()
    for i in range(len(P)):
        inverseP[P[i]] = i
        inverseS[S[i]] = i
    d = (math.floor(math.pow(n, 1.5)) + x) % n
    M = [""] * n
    M[d] = P[inverseS[c[d]]]
    for i in range(n-1):
        M[(d-i-1) % n] = P[inverseS[c[(d-i-1) % n]] ^ inverseS[M[(d-i) % n]]]

    return "".join(M)

# do decryption challenges
r.recvuntil(b": ")
r.send("\n".encode())
r.recvuntil(b": ")
r.send("4\n".encode())

for i in range(65, 201):
    res = r.recvline()
    c = res[:len(res)].decode().strip()
    m = decrypt(c, S, P, x)
    r.recvuntil(b".")
    r.send((m+"\n").encode())

import base64
print(base64.b64decode(decrypt(r.recvline().decode().strip(), S, P, x)).decode())

r.close()