# just code, not a proper writeup

import base64

data = base64.b64decode("cht6Y23ZtWEaRvPL82pyWXBLmR9ZIrjkHbGXEYsSIpvUsJiyREeT+VKDOYxIEfxeZe8EBF5emHgYHstYiqcQ476SPOObwI2XsXCDWuHI45eaoPpQMUz+8CV+huEuTzcstlrj8UJcPF9IB3bXBtvOT9BtfK8eHQxTkpUYvm75Eb8O1afGN71xdco0DQESPhCywu3cGqUDyfbSRAQHr2TzJo6lHBOszcdV7YWrTn5ExDBXMRuWz47c7OhuvIO/1KIy3Q6raQgq27ydnTB23aVma2O3getjuEH0OTAAGFSpsVPGntJDU0HTwSQdyG8s5pLg7GqrvSZZEBb5/AMQnUzPu7EqC6ZbmHl+fRD/c8OhhgkRtQIvuYNLhN0tyLrKCRba+gt0Yc+sAMm+q9sUeUkSYs/3CivblY1xhl20eBSiaQlLXhunzKcNH2r9Eu/MkX953nKqqTjBw69D5NTmKTeVD8ltneO3xeCyq84QAvQYQV/o3GgJSEVW9wQX0YyS0k1lOMUfPszJlQAp6GPuUuTir+NMGM2gETXPPRgAmsky1W1DTV1sJLmqj4M4Htto89scFHKMKMMgoh9PoW21JUvUgLgZaQJ36WSjBizSblHLsAnWS97IckqZMfnpCnMcyhBhrBNaCK9ozEIN5Z3WwmL2/ZHasTtvgFQUm13WuojfdzGoWxz5kmCxZ9HWXOA+C9z+MQd1kEFTp0vKJPZ8Oy49jOnHgQDOV2JpXbusa9cap1OKrDaVuTTdA1PKcmQBSK9khZdOoTbFK4DzuzOz/1mYfb56PR594Zqf5bpc9igsGLqeCpcppCw4oMlF1IzTOUmID3FJ+yZLY52tt88SAtTVicjT44bhJ9Is7wxvJ+ARHnN2JZmgDlh/gJ7R3evhPwjPCDlI/cEC321YLIRQOZ/A0+UoXNoOneWmjbhTDIVAri1+hiSErXperhZMpBc51AmCJK1RJhDlln7S8jaGFUImeZPnpWE89rsd9i7L0HvsAcyGfHxqB8QTdb4ipnwl2h5umhCix5h/3CF26gi9uBmdfpXavt1v3U2CEcpYvWhEgLRAtvJJCzZ4TyNVxjcoU7fZZy+/bGddasig+PHTf3MLCOjshFasKY5IW9oLoX3/aqu8qmdhPt9joAU+XSkprPC1bqjV00om1fsoC8RuuqGkwb2PCApqXzMnt2bGtFxPKMZFzwZ4AcDlBpJlDaXJ31UmjoXQfQuWYYsjYJiaBh1NzMgNUKMGLJRkb1Ajq/JyKXIanqAX84bnBNICLDf3DOM2ZNPWx/GMFt7i0ZNJDZFVeMYRUpLVnpQQlHwy6NhG0ME6NfV//vdX8AldYNi6WmtIuGeoSdExiLmbdGFr++7eGF10OWKwvvEBnuRr1bYIkHQs3kvby/miMK6SdtVyqnGmE7qfZo3/l1ajLAsAcAdM6DS24/rSrT3tq3QcB7TxS7noEQaRiONoHrq0ZC+AwzQiUm3M9nxCCVt+XzogYvIQpTwOa64ZC08zREihmkhZrNbXoazMUgZBqgQVU0wegnYRNfMd953E2d1ma+j/k6Gj4DOZy09athcTM+RlFBbf8tZNCA3m7tjtgu6T0mC22TGPtBq6fkZPVQibr5Iwv+908wW79g48+iKp272cML8ZWoB6A1WRdJLKN+CEO78RyNXZ39FPyXiz6R7SLX+f8D4lpaBbdMtS6T/gPlZBGzBsEQl+jDUwDi6S50VJaHBlbYColaBEqThqEvE9VGTIQ6Ym5flXxZ/AyPyGvtFzaROhUr7f7HMZQz8181r9l7Qh+PGGbrAkbsDSHq7yg5KtiMCIU7UcORHX4q5yKEhbR6uGRLTymXPhwS2NJxTTAFu34uXLk7sQvHK7Fc6uSXmAUSRtmqcNQEt9sRgqYcS4vrcHN0WDBr60woDxWtcBhAaUiohXouRtMMfYEiM4W4nb2MD7HnYKIQFQoDL/DfEpGoh/rjNiVPLwFRNcA70qvmpD68CdHmQ60W/E9BVz0wNwyIoA6vzOaa0xMD2UoV5HCs7w58SZW+D8jB5tVIPgH74rdsbXrvu/e9TKYg7/RZE8YrNzAbqL5m8Za/JVUMww2opcIvWcPtKH5KNRiRyQDQBhZguo1/piufNLaS6yjnlj3XGv0sK5AhacgR8CVzqMXfW7fM4fWGghNqQRkcNoolLYYo3KYQq7wijMU/QwOWkZ0zYaNXNtpVU7dYXZSLulhLoITPnO3oLwXjv3wPIXu0giXpMVXot3UmTY8Phs8qmbifNjnsW++WjHy+izwiYnoLGgvj+fjejiImPYSUgqvHSki6TrMtdrDvqJ2e3HddLYU97aBLR2IpRhXaD5w0OupjLDQohWmao/Cqml/ulNnlgoTl2AOWdBTs5v1OUSmZFagMXzuznalk2ieNqeOK/wmGDPjfQZhm1p9DS3ioiEsJGtkpNpp0OlM8ayWh4ULSgV+ukwE1R0iHMXx0l9coVWVw24MM3w6VnX2bz69Y+2lLw=")
crib = b"cybersecurityBE"

def xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def generate_full_pad(key, i):
    global data
    pad = [-1]*(len(data)+1)
    for j in range(16):
        pad[i+j] = key[j]
    # compupte backwards
    for j in range(i-1, -1, -1):
        pad[j] = pad[j+1] ^ pad[j+2] ^ pad[j+3] ^ pad[16 + j]
    # extend forward
    for j in range(i, len(pad)-16):
        pad[j+16] = pad[j] ^ pad[j+1] ^ pad[j+2] ^ pad[j+3]
    return pad


for i in range(len(data)-len(crib)): # test all possible postions
    for b in range(256): # guess last byte
        key = list(x for x in xor(data[i:i+len(crib)], crib))
        key.append(b)
        pad = generate_full_pad(key, i)
        res = xor(data, pad[:len(pad)-1])
        try:
            res = xor(data, pad[:len(pad)-1]).decode()
            if "CSC{" in res:
                print(res[res.index("CSC{"):res.index("}")+1])
        except:
            pass

