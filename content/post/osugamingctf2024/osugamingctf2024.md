---
title: osu!gaming CTF 2024
date: 2024-03-04
math: true
tags: [prng,hash,rsa]
draft: false
---

## はじめに

osu!gaming CTF 2024 に sayonara で参加して 120位 でした．

cryptoは全8問でしたが自分は4問解きました．

他メンバーが２問解いたのでチームとしては６問解けました．成長してきたかも．

そういえば人生で初めて nc で接続する系の問題を解いた笑．

ずっとpwntoolsの使い方が分からず逃げ続けていたのだが，今回でかなりわかった気がする．

その問題のsolverは間違いなく自分史上最長のsolverになった．

相変わらずプログラミングは嫌いだが，できることが増えていくのは楽しい．

## base727 (104pt)

### source

727.py

```python
import binascii

flag = open('flag.txt').read()

def encode_base_727(string):
    base = 727
    encoded_value = 0

    for char in string:
        encoded_value = encoded_value * 256 + ord(char)

    encoded_string = ""
    while encoded_value > 0:
        encoded_string = chr(encoded_value % base) + encoded_string
        encoded_value //= base

    return encoded_string

encoded_string = encode_base_727(flag)
print(binascii.hexlify(encoded_string.encode()))
```

out.txt

```
06c3abc49dc4b443ca9d65c8b0c386c4b0c99fc798c2bdc5bccb94c68c37c296ca9ac29ac790c4af7bc585c59d
```

### description

解説することは特に無い．

### solver

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

def decode_base_727(encoded_string):
    base = 727
    decoded_value = 0

    for char in encoded_string:
        decoded_value = decoded_value * base + ord(char)

    decoded_string = ""
    while decoded_value > 0:
        decoded_string = chr(decoded_value % 256) + decoded_string
        decoded_value //= 256

    return decoded_string


ct = long_to_bytes(int('06c3abc49dc4b443ca9d65c8b0c386c4b0c99fc798c2bdc5bccb94c68c37c296ca9ac29ac790c4af7bc585c59d',16))

flag = decode_base_727(ct.decode())

print(flag)
```

flag

```
osu{wysiwysiwysiywsywiwywsi}
```

## ROSSAU (105pt)

### source

問題文に $n,\ e$ が書いてある．

```
n = 5912718291679762008847883587848216166109
e = 876603837240112836821145245971528442417
```

### description

$n,\ e$ はRSAの公開鍵だと予想できる．容易に素因数分解できるので $d$ を求められる．

最後に，osu!のプレイヤーIDが $d$ であるプレイヤーを検索し，その名前が flag となる．

### solver

```python
p,q = factor(5912718291679762008847883587848216166109)

e = 876603837240112836821145245971528442417

phi = 59644326261100157130 * 99132954671935298038

d = pow(e,-1,phi)

print(d)
```

flag

```
osu{chocomint}
```

## korean-offline-mafia (126pt)

### source

```python
from topsecret import n, secret_ids, flag
import math, random

assert all([math.gcd(num, n) == 1 for num in secret_ids])
assert len(secret_ids) == 32

vs = [pow(num, 2, n) for num in secret_ids]
print('n =', n)
print('vs =', vs)

correct = 0

for _ in range(1000):
	x = int(input('Pick a random r, give me x = r^2 (mod n): '))
	assert x > 0
	mask = '{:032b}'.format(random.getrandbits(32))
	print("Here's a random mask: ", mask)
	y = int(input('Now give me r*product of IDs with mask applied: '))
	assert y > 0
	# i.e: if bit i is 1, include id i in the product--otherwise, don't
	
	val = x
	for i in range(32):
		if mask[i] == '1':
			val = (val * vs[i]) % n
	if pow(y, 2, n) == val:
		correct += 1
		print('Phase', correct, 'of verification complete.')
	else:
		correct = 0
		print('Verification failed. Try again.')

	if correct >= 10:
		print('Verification succeeded. Welcome.')
		print(flag)
		break
```

### description

getrandbits(32) で生成される乱数を1000個まで取得できるので，メルセンヌ・ツイスタの内部状態を再現できる．

次にサーバーで生成される乱数をローカルで確認し，vsから選ばれる値 $s_{i}^2 \mod n$ の逆元の積 $x$ を送る．[^1]

$$
x = \prod_i (s_{i}^2)^{-1} \mod n
$$

そうすると，常に $val=1$ となるため $y=1$ を送ってやればいい．[^2]

[^1]: $\gcd(s_i,n)=1$ であるから $\gcd(s_i^2,n)=1$ であり，ちゃんと $(s_{i}^2)^{-1}$ は存在する．

[^2]: $x,\ y$ のinputのところに何か書いているが，実際は正の整数であれば何を送っても良い．

### solver

```python
from pwn import *
import subprocess
import math
from mt19937predictor import MT19937Predictor


predictor = MT19937Predictor()
count = 0
count3 = 0
mask_list = []

# ncで繋げると curl コマンドが送られてくる．
# それをターミナルで実行するとテキストが返ってきて，そのテキストをproof of workに提出するとやっとncに繋がる．
io = remote("chal.osugaming.lol" ,7275)
io.recvuntil(b'proof of work:')
io.recvline()
work = io.recvline().decode()
test = subprocess.run(work, shell=True, capture_output=True, text=True)
io.send(test.stdout.encode())

# n, vsを受け取る．
io.recvuntil(b'n =')
n = int(io.recvline().split()[0])
io.recvuntil(b'vs =')
vs = io.recvline().decode()[2:-2].split(',')
vs = [int(i) for i in vs]
vs_inv = [pow(i,-1,n) for i in vs]


for i in range(650):
    if count >= 624:
        count2 = 0
        r = 1
        if count == 624:
            for x in mask_list:
                predictor.setrandbits(x,32)
        new_mask = '{:032b}'.format(predictor.getrandbits(32))
        for j in new_mask:
            if j == '1':
                r = (r*vs_inv[count2])%n
            count2 += 1
        io.sendlineafter(b'Pick a random r, give me x = r^2 (mod n): ', str(r).encode())
        io.recvuntil(b"Here's a random mask: ")
        gomi = io.recvline().decode()
        y = 1
        io.recvuntil(b'Now give me r*product of IDs with mask applied: ')
        io.sendline(str(y).encode())
        print(io.recvline())
        count += 1
        count3 += 1
        print('count3',count3)
        if count3 == 10:
            print(io.recvline())
            print(io.recvline())
            print(io.recvline())
    else:
        io.sendlineafter(b'Pick a random r, give me x = r^2 (mod n): ', str(1).encode())
        io.recvuntil(b"Here's a random mask: ")
        mask = io.recvline().decode()
        # print(mask)
        mask_list.append(int(mask,2))
        y = 1
        io.sendlineafter(b'Now give me r*product of IDs with mask applied: ', str(y).encode())
        count += 1
        print(count)
```

### 思い出話

朝９時頃に問題に取り組み始め，15分くらいで解法がわかった．

しかし，この問題の flag を入手したのは深夜1時30分であった．．．

ずっと何をしてたかと言うと，pwntoolsの使い方およびプログラミングのエラーと闘っていました笑

最後はチームのdiscord内で画面共有し，rev担当のメンバーに見守られながら flag ゲット．

僕のぐちゃぐちゃ solver を見て，「revでこんな感じの難読化手法ありますよ」と言われたときはめっちゃ笑った．

（writeupのsolverは整形したもの（整形できているのか？））

懐かしアニメの雑談をしながらsolver書いてたから深夜の作業でも心折れなかった説ある．

チームでCTFできるっていいなって思った．

それはそれとして，さくさく実装できるようになりたい泣．


## no-dorchadas (133pt)

### source

```python
from hashlib import md5
from secret import flag, secret_slider
from base64 import b64encode, b64decode

assert len(secret_slider) == 244
dorchadas_slider = b"0,328,33297,6,0,B|48:323|61:274|61:274|45:207|45:207|63:169|103:169|103:169|249:199|249:199|215:214|205:254,1,450.000017166138,6|6,1:1|2:1,0:0:0:0:"

def sign(beatmap):
    hsh = md5(secret_slider + beatmap)
    return hsh.hexdigest()

def verify(beatmap, signature):
    return md5(secret_slider + beatmap).hexdigest() == signature

def has_dorchadas(beatmap):
    return dorchadas_slider in beatmap

MENU = """
--------------------------
| [1] Sign a beatmap     |
| [2] Verify a beatmap   |
--------------------------"""

def main():
    print("Welcome to the osu! Beatmap Signer")
    while True:
        print(MENU)
        try:
            option = input("Enter your option: ")
            if option == "1":
                beatmap = b64decode(input("Enter your beatmap in base64: "))
                if has_dorchadas(beatmap):
                    print("I won't sign anything with a dorchadas slider in it >:(")
                else:
                    signature = sign(beatmap)
                    print("Okay, I've signed that for you: " + signature)
            elif option == "2":
                beatmap = b64decode(input("Enter your beatmap in base64: "))
                signature = input("Enter your signature for that beatmap: ")
                if verify(beatmap, signature) and has_dorchadas(beatmap):
                    print("How did you add that dorchadas slider?? Anyway, here's a flag: " + flag)
                elif verify(beatmap, signature):
                    print("Signature is valid!")
                else:
                    print("Signature is invalid :(")
        except:
            print("An error occurred!")
            exit(-1)

main()
```

### description

Length Extension Attack をする．

### solver

```python
from pwn import *
import subprocess
import HashTools
from base64 import b64encode

# https://github.com/viensea1106/hash-length-extension

m1 = b'sayonara'
m2 = b"0,328,33297,6,0,B|48:323|61:274|61:274|45:207|45:207|63:169|103:169|103:169|249:199|249:199|215:214|205:254,1,450.000017166138,6|6,1:1|2:1,0:0:0:0:"

io = remote("chal.osugaming.lol" ,9727)
io.recvuntil(b'proof of work:')
io.recvline()
work = io.recvline().decode()
test = subprocess.run(work, shell=True, capture_output=True, text=True)
io.send(test.stdout.encode())

io.recvuntil(b"Enter your option: ")
io.sendline(b'1')
io.recvuntil(b"Enter your beatmap in base64: ")
io.sendline(b64encode(m1))
io.recvuntil(b"Okay, I've signed that for you: ")
sig = io.recvline()
sig = 'b9d10c520620917cdbf909a5b724ec18'
magic = HashTools.new('md5')
new_data, new_sig = magic.extension(secret_length=244, original_data=m1,append_data=m2, signature=sig)
print(new_data)
print(new_sig)
print(len(new_data))

io.recvuntil(b"Enter your option: ")
io.sendline(b'2')
io.recvuntil(b"Enter your beatmap in base64: ")
io.sendline(b64encode(new_data))
io.recvuntil(b"Enter your signature for that beatmap: ")
io.sendline(new_sig.encode())
print(io.recvline())
print(io.recvline())
io.recvuntil(b"How did you add that dorchadas slider?? Anyway, here's a flag: ")
print(io.recvline())
print(io.recvline())
```