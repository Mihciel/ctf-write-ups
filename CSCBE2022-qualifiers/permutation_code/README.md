# Permutation code
## problem description
This challenge provides us with an encryption oracle for the permutation code described on this site https://open.kattis.com/problems/permcode. The goal is to retrieve enough information from the oracle to decrypt the encrypted flag. The encrypted flag is only returned when one is able to decrypt some challenge ciphertexts with only a limited number of oracle calls (18 for the last flag). The oracle only provides encryptions for messages of maximal length 65.

## Plan of attack
To retrieve the last flag, permutations $P$ and $S$ as well as the integer $x$ have to be recovered within 18 oracle calls. We'll first convert the problem a SMT-model to recover $P$ and $S$, as well as $d(n)$. With this $d(n)$, $x \equiv d(n) - \lfloor n^{1.5}\rfloor\; \textrm{mod}\; n$ can be recovered. We notice in the code that $x$ is computed as follows.
```python
minX = functools.reduce(lambda a,b: a * b // math.gcd(a,b), range(1, MAX_MESSAGE_LENGTH + 1), 1)
x = minX + secrets.randbelow(minX)
```
This means that $x$ can be recovered if we know $x\; \textrm{mod} \;minX$.
Which in turn can be recovered using the Chinese Remainder Theorem if we know $x\; \textrm{mod} \;p$ for all prime powers $p\leq 65$. Finally, a decryption function
should be written to decrypt the challenges as well as the key.

The following code will get us started:

```python
import functools
import string
alphabet = string.ascii_letters + string.digits + "+/" # Base64 characters
invalph = {}
for i in range(len(alphabet)):
    invalph[alphabet[i]] = i


minX = functools.reduce(lambda a,b: a * b // math.gcd(a,b), range(1, 65 + 1), 1)

def encryption_oracle(m):
    # calls the encryption oracle and returns the encryption of the given message m
    pass
```

## SMT-model
Let us introduce two notations $P[x]$ is the character in $P$ at position $x$, $P_y$ is the index of the character $y$ in $P$. The two operations of the encryption are:
$$c[d]=S\left[P_{m[d]}\right]$$
$$c[i]=S\left[P_{m[j]}\oplus S_{m[j+1]}\right].$$
Notice that this can be rewritten to equations that only depend on the indices of characters in $P$ and $S$:
$$S_{c[d]}=P_{m[d]}$$
$$S_{c[i]}=P_{m[j]}\oplus S_{m[j+1]}.$$
Since knowing the index of each character in both $P$ and $S$ is sufficient to retrieve the key, we'll use these equations to build the SMT model. Let us first create the variables that will hold these indices. Since there are 64 characters and xors between the indices are required, we decide to use bitvectors of length 6 (we use z3 as the SMT solver):
```python
from z3 import *
s = Solver()
pindices = [BitVec(f"p{x}", 6) for x in range(64)]
sindices = [BitVec(f"s{x}", 6) for x in range(64)]
```
Furthermore, each index is unique, so they can't be equal to each other. We add these constraints:
```python
for i in range(len(alphabet)):
    for j in range(len(alphabet)):
        if i != j:
            s.add(pindices[i] != pindices[j])
            s.add(sindices[i] != sindices[j])
```
Now for each plaintext-ciphertext pair, extra constraints can be added based on the equations given above. The variable $d$ is introduced as an integer between 0 and the length of the plaintext.
```python
def add_pc_constraints(s, m, c, pindices, sindices):
    d = Int(f"d{m}")
    s.add(0<=d<len(m))
    for i in range(len(m)):
        # add if then else statement as constraint
        s.add(If(d == i, sindices[invalph[c[i]]] == pindices[invalph[m[i]]], sindices[invalph[c[i]]] == (pindices[invalph[m[i]]] ^ sindices[invalph[m[(i+1)%len(m)]]])))
    return d
```
With this, the full cipher is encoded into an SMT-model. Which plaintexts to use will depend on how $x$ is recovered. But one important thing is that it contains as much unique information as possible. This can be accomplished by making the ciphertexts random.

## Recovering $x$
As discussed, we can use CRT to recover $x$. However, we need to know $x\; \textrm{mod}\;p$ for all prime powers $p \leq 65$. These are:
$2, 3, 4, 5, 7, 8, 9, 11, 13, 16, 17, 19, 23, 25, 27, 29, 31, 32, 37, 41, 43, 47, 49, 53, 59, 61$ and $64$. These are 27, however, only 18 oracle calls can be performed, luckily all primes that have a higher power in this list, can be omitted, because their value for $x$ can be computed from that of a higher power. This results in exactly 18 possibilities. To increase the amount of data to give to the SMT-solver, we'll also take the largest multiple less than or equal to 65 of these prime powers.
```python
import random
lengths = [64, 27*2, 25*2, 49, 11*5, 13*5, 17*3, 19*3, 23*2, 29*2, 31*2, 37, 41, 43, 47, 53, 59, 61]
dvars = []
for n in lengths:
    m = "".join(random.choices(alphabet, k=n))
    c = encrypt(m)
    dvars.append(add_pc_constraints(s, m, c, pindices, sindices))
```
Now that all constraints are in place, the model can be solved and the $d$'s can be extracted and subsequently be used to compute $x\; \textrm{mod}\;n$:
```python
import math
if not s.check():
    print("no SMT model")
    exit()
# the model is wrong about 10% of the time, this will give an error further on in the code
model = s.model()

xmods = [(model[dvars[i]].as_long() - math.floor(math.pow(lengths[i], 1.5))) % lengths[i] for i in range(len(lengths))]
```
Now $x$ itself can be recovered using CRT:
```python
from sympy.ntheory.modular import crt
x = (crt(lengths, xmods)[0] % minX) + minX
```
And Finally, we also recover $P$ and $S$
```python
Ps = ["="]*64
Ss = ["="]*64
for i in range(len(alphabet)):
    pind = model[pindices[i]].as_long()
    sind = model[sindices[i]].as_long()
    Ps[pind] = alphabet[i]
    Ss[sind] = alphabet[i]

P = "".join(Ps)
S = "".join(Ss)
```

## Decrypting
The decryption function has to reverse the operations of the encryption function:
```python
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
```

## Complete code
To complete the challenge, some random decryptions have to be performed and the flag has to be decoded. The full code can be found in [solution.py](solution.py).