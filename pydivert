import socket
import threading
import os
import json
import urllib.request

import pydivert

LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8080

FAKE_SNI = b"snapp.ir"
FAKE_TTL = 4          # باید به DPI برسد ولی به سرور نرسد (3 تا 8 امتحان کن)
FAKE_MODE = "ttl"     # "ttl" یا "badsum" (چک‌سام خراب)

DNS_CACHE = {}


def resolve_ip(host):
    if host in DNS_CACHE:
        return DNS_CACHE[host]
    try:
        url = f"https://1.1.1.1/dns-query?name={host}&type=A"
        req = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
        with urllib.request.urlopen(req, timeout=5) as res:
            for ans in json.loads(res.read().decode()).get('Answer', []):
                if ans.get('type') == 1:
                    DNS_CACHE[host] = ans['data']
                    return ans['data']
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(host)
        DNS_CACHE[host] = ip
        return ip
    except Exception:
        return None


# ---------- ساخت ClientHello جعلی معتبر ----------
def _ext(t, data):
    return t.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def build_fake_tls_hello(sni):
    n = len(sni)
    sni_ext = _ext(0, (n + 3).to_bytes(2, 'big') + b"\x00" + n.to_bytes(2, 'big') + sni)
    groups = _ext(10, b"\x00\x06\x00\x1d\x00\x17\x00\x18")
    sigalgs = _ext(13, b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x03")
    versions = _ext(43, b"\x04\x03\x04\x03\x03")
    exts = sni_ext + groups + sigalgs + versions

    ciphers = b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
    body = (
        b"\x03\x03" + os.urandom(32) +
        b"\x20" + os.urandom(32) +
        len(ciphers).to_bytes(2, 'big') + ciphers +
        b"\x01\x00" +
        len(exts).to_bytes(2, 'big') + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, 'big') + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, 'big') + hs


FAKE_HELLO = build_fake_tls_hello(FAKE_SNI)


# ---------- تزریق بستهٔ جعلی با WinDivert ----------
def divert_loop():
    flt = "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0"
    with pydivert.WinDivert(flt) as w:
        print("[*] WinDivert active: injecting fake SNI =", FAKE_SNI.decode())
        for pkt in w:
            try:
                p = pkt.tcp.payload
                # فقط ClientHello واقعی (و نه بستهٔ جعلی خودمان)
                if p and len(p) > 6 and p[0] == 0x16 and p[5] == 0x01 and FAKE_SNI not in p:
                    fake = pydivert.Packet(bytearray(pkt.raw), pkt.interface, pkt.direction)
                    fake.tcp.payload = FAKE_HELLO       # seq/ack همان بستهٔ واقعی است

                    if FAKE_MODE == "ttl":
                        fake.ipv4.ttl = FAKE_TTL
                        w.send(fake)                    # چک‌سام درست محاسبه می‌شود
                    else:
                        fake.recalculate_checksums()
                        fake.tcp.cksum = (fake.tcp.cksum + 1) & 0xFFFF
                        w.send(fake, recalculate_checksum=False)

                    print(f"[+] fake hello injected -> {pkt.dst_addr}:{pkt.dst_port}")
            except Exception as e:
                print("[!] inject error:", e)
            w.send(pkt)                                 # بستهٔ واقعی بدون تغییر


# ---------- پروکسی ----------
def pipe(src, dst):
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.close()
            except Exception:
                pass


def recv_headers(sock):
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 16384:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_client(client):
    remote = None
    try:
        req = recv_headers(client)
        if not req:
            client.close()
            return
        first = req.split(b"\r\n")[0].decode('latin1')
        if not first.startswith('CONNECT'):
            client.close()
            return

        host, port = first.split(' ')[1].rsplit(':', 1)
        ip = resolve_ip(host)
        if not ip:
            client.close()
            return

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote.settimeout(8)
        remote.connect((ip, int(port)))
        remote.settimeout(None)

        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # ClientHello واقعی را همان‌طور می‌فرستیم؛ WinDivert قبلش بستهٔ جعلی را تزریق می‌کند
        first_data = client.recv(16384)
        if first_data:
            remote.sendall(first_data)
            print(f"[+] {host} ({ip})")

        threading.Thread(target=pipe, args=(client, remote), daemon=True).start()
        threading.Thread(target=pipe, args=(remote, client), daemon=True).start()
    except Exception:
        for s in (client, remote):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def main():
    threading.Thread(target=divert_loop, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(200)
    print(f"[*] Fake-SNI proxy on {LISTEN_HOST}:{LISTEN_PORT}")
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle_client, args=(c,), daemon=True).start()


if __name__ == '__main__':
    main()
