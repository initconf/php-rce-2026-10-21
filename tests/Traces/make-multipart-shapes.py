#!/usr/bin/env python3
"""Build a synthetic pcap of benign-shaped multipart POSTs to exercise
detect-php-upload-progress.zeek. Pure stdlib; no checksums (run zeek with -C).
Nothing here is an exploit: every body is ordinary form data; only the *shape*
matches what the 2026-10-21 PHP advisories describe.

Flows (external 93.184.216.34 -> internal 128.3.1.10:80):
  1. plain multipart form with a small text file                -> no notice
  2. same + PHP_SESSION_UPLOAD_PROGRESS part + PHPSESSID cookie -> Progress_With_Sid
  3. same + progress part, no session id                        -> Progress_Field
  4. 45 trivial text parts, server answers 502                  -> Many_Parts + Multipart_5xx
  5. chunked transfer-encoding, no Content-Length               -> Multipart_No_Length
  6. one part carrying 12 headers                               -> Many_Part_Headers
  7. 12 empty file parts                                        -> Many_Empty_Files
  8. a field named a[b][c]...  (14 levels)                      -> Deep_Nesting
  9. ordinary form, server resets without replying              -> Multipart_No_Reply
 10. plain POST, not multipart, 45 urlencoded fields            -> no notice (control)
"""
import struct, sys, time

OUT = sys.argv[1] if len(sys.argv) > 1 else "test-upload-progress.pcap"
# Not a TEST-NET address: Zeek's default Site::local_nets treats 203.0.113.0/24 etc. as local.
CLI, SRV = "93.184.216.34", "128.3.1.10"
BOUND = "----ZeekTestBoundary7MA4YWxk"

def ip(a): return bytes(int(x) for x in a.split("."))

def pkt(src, sport, dst, dport, seq, ack, flags, payload=b""):
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, ip(src), ip(dst))
    return eth + iph + tcp

def part(name, value, filename=None, ctype=None, extra_headers=()):
    h = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        h += f'; filename="{filename}"'
    h += "\r\n"
    if ctype:
        h += f"Content-Type: {ctype}\r\n"
    for k, v in extra_headers:
        h += f"{k}: {v}\r\n"
    return f"--{BOUND}\r\n{h}\r\n{value}\r\n"

def request(parts, cookie=None, uri="/index.php", chunked=False):
    body = "".join(parts) + f"--{BOUND}--\r\n"
    hdr = (f"POST {uri} HTTP/1.1\r\nHost: www.example.lbl.gov\r\n"
           f"User-Agent: zeek-test/1.0\r\nContent-Type: multipart/form-data; boundary={BOUND}\r\n")
    if cookie:
        hdr += f"Cookie: {cookie}\r\n"
    if chunked:
        hdr += "Transfer-Encoding: chunked\r\n\r\n"
        b = body.encode()
        out = b""
        for off in range(0, len(b), 700):
            seg = b[off:off + 700]
            out += f"{len(seg):x}\r\n".encode() + seg + b"\r\n"
        return hdr.encode() + out + b"0\r\n\r\n"
    hdr += f"Content-Length: {len(body)}\r\n"
    return (hdr + "\r\n" + body).encode()

def urlencoded(n):
    body = "&".join(f"f{i}=v{i}" for i in range(n))
    return (f"POST /index.php HTTP/1.1\r\nHost: www.example.lbl.gov\r\nUser-Agent: zeek-test/1.0\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n\r\n{body}").encode()

def response(code, reason):
    body = b"<html>ok</html>\n"
    return (f"HTTP/1.1 {code} {reason}\r\nServer: Apache\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body

base = [part("title", "hello"), part("upload", "some text\n", "notes.txt", "text/plain")]
many_hdrs = [(f"X-Meta-{i}", f"v{i}") for i in range(10)]
nested = "a" + "".join(f"[k{i}]" for i in range(14))
flows = [
    (request(base), response(200, "OK")),
    (request([part("PHP_SESSION_UPLOAD_PROGRESS", "abc")] + base, cookie="PHPSESSID=testsession1"), response(200, "OK")),
    (request([part("PHP_SESSION_UPLOAD_PROGRESS", "abc")] + base), response(200, "OK")),
    (request([part("t[]", "x") for _ in range(45)] + base), response(502, "Bad Gateway")),
    (request(base, chunked=True), response(200, "OK")),
    (request([part("meta", "x", extra_headers=many_hdrs)] + base), response(200, "OK")),
    (request([part(f"f{i}", "", filename="", ctype="application/octet-stream") for i in range(12)] + base), response(200, "OK")),
    (request([part(nested, "x")] + base), response(200, "OK")),
    (request(base), None),                       # server resets, no reply
    (urlencoded(45), response(200, "OK")),
]

frames = []
t = time.time()
for i, (req, resp) in enumerate(flows):
    sport = 40000 + i
    cs, ss = 1000, 5000
    frames.append(pkt(CLI, sport, SRV, 80, cs, 0, 0x02));            cs += 1       # SYN
    frames.append(pkt(SRV, 80, CLI, sport, ss, cs, 0x12));            ss += 1       # SYN/ACK
    frames.append(pkt(CLI, sport, SRV, 80, cs, ss, 0x10))                           # ACK
    for off in range(0, len(req), 1400):                                             # request
        seg = req[off:off + 1400]
        frames.append(pkt(CLI, sport, SRV, 80, cs, ss, 0x18, seg)); cs += len(seg)
    frames.append(pkt(SRV, 80, CLI, sport, ss, cs, 0x10))                           # ACK
    if resp is None:
        frames.append(pkt(SRV, 80, CLI, sport, ss, cs, 0x14))                       # RST/ACK
        continue
    frames.append(pkt(SRV, 80, CLI, sport, ss, cs, 0x18, resp));     ss += len(resp)
    frames.append(pkt(CLI, sport, SRV, 80, cs, ss, 0x11));            cs += 1       # FIN
    frames.append(pkt(SRV, 80, CLI, sport, ss, cs, 0x11));            ss += 1
    frames.append(pkt(CLI, sport, SRV, 80, cs, ss, 0x10))

with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for n, fr in enumerate(frames):
        ts = t + n * 0.01
        f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr)
print(OUT, len(frames), "frames")
