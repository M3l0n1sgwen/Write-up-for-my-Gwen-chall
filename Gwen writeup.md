---
title: Gwen writeup

---

Chào mọi người nhé! Hôm nay tôi sẽ hướng dẫn mọi người giải câu đố CTF tôi ra hôm bữa nha hẹ hẹ!

Đề bài:

![image](https://hackmd.io/_uploads/HJYIYCvr-e.png)

Phân tích sơ bộ:
-Dạng bài:steganography
-có key: DS03-hard-2026

Phân tích sâu:
-Đầu tiên, hãy thử sài **exiftool** xem author có giấu hint/flag (mức độ dễ sẽ có) ở ảnh luôn không?

![image](https://hackmd.io/_uploads/r1PTcAwHWe.png)

Chúng ta thấy ở đây rất bình thường, không có manh mối nào khi xài exiftool

Hãy thử nghĩ đến hướng **LSB** (1 hướng cũng rất phổ biến ở các dạng bài steno)

**Note: LSB hay Least Significant Bit : Bit có trọng số thấp nhất trong tin học, chỉ bit ở ngoài cùng bên phải, có giá trị nhỏ nhất trong dãy bit**

Sử dụng câu lệnh **zsteg** (dùng để phát hiện và trích xuất dữ liệu bị giấu trong ảnh) ta có được:

![image](https://hackmd.io/_uploads/Sy5AhRwH-g.png)

Okay ở dòng 2 ta thấy được 1 cái văn bản khá bình thường là **STEGv10y{y**, đây là **MAGIC** (dãy ma thuật, hãy tìm hiểu về cấu trúc pe file và bạn sẽ hiểu công dụng của nó) và hãy chú ý điều này 

Quên mất k ghi ở câu hỏi cho mọi người, đây là kiểu khóa **AES-GCM** 

Để giải khóa **AES-GCM** cần các yếu tố ở trên hình:
![image](https://hackmd.io/_uploads/r1RBfy_SZe.png)


Khá phức tạp ha =))) Vậy thì đã đến lúc chatGPT vào cuộc rồi.
Hãy để con chatbot làm việc của nó: decrypt hoặc bạn có thể tham khảo cách giải mã của tôi, dĩ nhiên cũng từ chat mà ra =))

Note: Thực ra dãy MAGIC đúng là **STEGv1**, các bạn chuyển sang bit sẽ thấy phần từ 0 trở đi là phần dư ra.

Dùng code này đầu tiên xác định **salt, nonce và ciphertext** nhé:
```
from pathlib import Path

MAGIC = b"STEGv1"   

p = Path("payload.bin").read_bytes()

if not p.startswith(MAGIC):
    raise SystemExit(f"Magic mismatch. Found={p[:len(MAGIC)]!r}")

rest = p[len(MAGIC):]
print("rest len:", len(rest))
print("rest head:", rest[:32].hex(" "))

salt = rest[:16]
nonce = rest[16:28]    
ct = rest[28:]

Path("salt.bin").write_bytes(salt)
Path("nonce.bin").write_bytes(nonce)
Path("ct.bin").write_bytes(ct)

print("salt:", salt.hex())
print("nonce:", nonce.hex())
print("ct bytes:", len(ct))
```
Ok sau đó sài code này để giải mã:

```
from pathlib import Path
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

PASS = b"DS03-hard-2026"

p = Path("payload.bin").read_bytes()
assert p.startswith(b"STEGv1")
rest = p[len(b"STEGv1"):]

# bạn đã thấy rest bắt đầu bằng: 30 79 7b 79 ...
# ở đây ta thử 2 khả năng:
# A) rest[0] là version byte (0x30 = '0'), dữ liệu bắt đầu từ rest[1:]
# B) rest không có version byte, dữ liệu bắt đầu ngay rest[0:]
candidates_rest = [
    ("rest0", rest),
    ("rest1", rest[1:]),
    ("rest3", rest[3:]),  # phòng trường hợp "y{y" là marker
]

def kdf_pbkdf2(salt, iters):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters)
    return kdf.derive(PASS)

def kdf_scrypt(salt, n=2**14, r=8, p=1):
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(PASS)

def kdf_sha256(salt):
    return hashlib.sha256(PASS + salt).digest()

AAD_LIST = [None, b"gwen-steg", b"STEGv10", b"gwencute", b"DS03"]

# thử các iters phổ biến
PBKDF2_ITERS = [50_000, 100_000, 200_000, 300_000, 500_000]

def try_one(label, salt, nonce, ct):
    # 1) SHA256(pass+salt) + AESGCM / ChaCha
    for aad in AAD_LIST:
        key = kdf_sha256(salt)
        for alg in ("AESGCM", "CHACHA"):
            try:
                if alg == "AESGCM":
                    pt = AESGCM(key).decrypt(nonce, ct, aad)
                else:
                    pt = ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
                return (label, f"sha256+{alg}", aad, pt)
            except Exception:
                pass

    # 2) PBKDF2 iters + AESGCM/ChaCha
    for it in PBKDF2_ITERS:
        key = kdf_pbkdf2(salt, it)
        for aad in AAD_LIST:
            for alg in ("AESGCM", "CHACHA"):
                try:
                    if alg == "AESGCM":
                        pt = AESGCM(key).decrypt(nonce, ct, aad)
                    else:
                        pt = ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
                    return (label, f"pbkdf2({it})+{alg}", aad, pt)
                except Exception:
                    pass

    # 3) scrypt + AESGCM/ChaCha
    for aad in AAD_LIST:
        try:
            key = kdf_scrypt(salt)
        except Exception:
            continue
        for alg in ("AESGCM", "CHACHA"):
            try:
                if alg == "AESGCM":
                    pt = AESGCM(key).decrypt(nonce, ct, aad)
                else:
                    pt = ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
                return (label, f"scrypt+{alg}", aad, pt)
            except Exception:
                pass

    return None

def looks_like(pt: bytes):
    if pt.startswith(b"PK\x03\x04"): return "ZIP"
    if pt.startswith(b"#!/usr/bin/env") or pt.startswith(b"import "): return "PY"
    if b"DS03{" in pt[:5000] or b"flag{" in pt[:5000] or b"CTF{" in pt[:5000]: return "FLAG_TEXT"
    return None

for rlabel, r in candidates_rest:
    if len(r) < 16+12+16:
        continue
    salt = r[:16]
    nonce = r[16:28]
    ct = r[28:]

    res = try_one(rlabel, salt, nonce, ct)
    if res:
        label, how, aad, pt = res
        kind = looks_like(pt)
        Path("recovered.bin").write_bytes(pt)
        print("[+] DECRYPT OK!")
        print("    rest =", label)
        print("    how  =", how)
        print("    aad  =", aad)
        print("    type =", kind)
        print("    wrote recovered.bin (len=%d)" % len(pt))
        break
else:
    print("[-] No variant worked.")
    print("    -> Nếu vẫn fail, khả năng cao: salt/nonce không đúng vị trí (parse khác), hoặc thuật toán khác.")
```

Kết quả:

![image](https://hackmd.io/_uploads/HknaXy_rWe.png)



Mở **recovered.bin** ta thấy file **gwen\.py**:

![image](https://hackmd.io/_uploads/SkiMNJ_Bbl.png)


Mở nó lên và ta thấy cái này:
```
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));
exec((_)(b'==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'))
```
Thử chạy nhé!
![image](https://hackmd.io/_uploads/SkL54y_rZe.png)

1 lệnh check input đơn giản được ngụy trang trông khó hiểu, đây là dạng **obfucated code**, hãy sài 1 số tool decrypt và bạn dễ dàng có đượcc dạng code ban đầu (quá trình deobfucated):
```
EXPECTED_FLAG = "DS03{2026_ro1_n3_cac_ba1}"

flag = input("Nhập flag: ").strip()

if flag == EXPECTED_FLAG:
    print("Đúng rồi!")
else:
    print("Sai cmnr!")

```

Vậy flag cho câu đố này là **DS03{2026_ro1_n3_cac_ba1}**,cảm ơn các bạn đã xem phần trình bày của mình OwO!