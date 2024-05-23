from pwn import remote, process
from random import randrange

while True:
    # r = process("./JuniorFeistel")
    r = remote("juniorfeistel.challs.open.ecsc2024.it", 38014)
    r.recvuntil(b"encrypt?\n")
    ps = []
    x = randrange(2**32)
    for j in range(1750000):
        ps.append(j*2**42 + x)
    r.sendline(" ".join([str(x) for x in ps]).encode())
    r.sendline(b"-1")
    cs = [
        tuple(map(int, l.split(", ")))
        for l in r.recvuntil(b"Key?").decode().splitlines()[:-1]
    ]
    filtered_pairs = []
    for d in [0x03fffc00, 0x04000400, 0x07fff800, 0x08000800, 0x0ffff000, 0x10001000]:
        for i in range(d>>10, 1750000):
            if cs[i][0] - cs[i-(d>>10)][0] == d:
                filtered_pairs.append(
                            (
                                ps[i-(d>>10)],
                                ps[i],
                                cs[i-(d>>10)],
                                cs[i],
                            )
                        )

    print(len(filtered_pairs))
    # guess key
    if len(filtered_pairs) > 5:
        p = process(
            "./better_deduce"
        )  # compile better_deduce_key.cpp (with openmp enabled) if this file doesn't exist
        p.sendline(f"{len(filtered_pairs)}".encode())

        for x in filtered_pairs:
            p.sendline(
                f"{x[0]>>32} {x[0]&0xffffffff} {x[1]>>32} {x[1]&0xffffffff} {x[2][0]} {x[2][1]} {x[3][0]} {x[3][1]}".encode()
            )
        k = int(p.recvline(timeout=10000).decode())
        p.close()
        print(k)
        r.sendline(str(k).encode())
        res = r.recvall()
        r.close()
        if b"openECSC" in res or b"Flag" in res:
            print(res)
            exit()
    else:
        r.close()
