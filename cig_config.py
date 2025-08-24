import sys, os, re, struct

MAGIC = b"CIGG"
FOOTER_LEN = 32
KEY = 0xAA

# ---------- helpers ----------
def bxor(b: bytes, key: int = KEY) -> bytes:
    k = key & 0xFF
    return bytes([x ^ k for x in b])

def autodetect_key(enc: bytes) -> int:
    cand = set()
    if len(enc) >= 2:
        cand |= {enc[-2] ^ 0x3E, enc[-1] ^ 0x0A, enc[-2] ^ 0x0D}
    for k in list(cand) + list(range(256)):  # fallback — полный перебор
        dec = bxor(enc[:4096], k)
        if dec.startswith(b'<?xml') or (b'<' in dec and b'>' in dec and b'</' in dec):
            return k
    return 0xAA

def crc32_bzip2_be(data: bytes) -> bytes:
    # CRC-32/BZIP2: poly 0x04C11DB7, init 0xFFFFFFFF, refin=False, refout=False, xorout=0xFFFFFFFF
    # Реализуем через табличный «неотражённый» вариант
    poly = 0x04C11DB7
    mask = 0xFFFFFFFF
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ poly) & mask if (c & 0x80000000) else ((c << 1) & mask)
        table.append(c & mask)
    crc = 0xFFFFFFFF
    for b in data:
        idx = ((crc >> 24) ^ b) & 0xFF
        crc = (table[idx] ^ ((crc << 8) & mask)) & mask
    crc ^= 0xFFFFFFFF
    return struct.pack(">I", crc)

def find_xml_end(xmlish: bytes) -> int:
    b = xmlish
    i = 0
    while i < len(b) and b[i] in (0x20,0x09,0x0d,0x0a,0xef,0xbb,0xbf): i += 1
    if i < len(b) and b[i:i+5].lower() == b'<?xml':
        j = b.find(b'?>', i)
        if j != -1:
            i = j + 2
            while i < len(b) and b[i] in (0x20,0x09,0x0d,0x0a): i += 1
    if i >= len(b) or b[i] != 0x3C:
        last = b.rfind(b'>'); return last + 1 if last != -1 else len(b)
    m = re.match(br'<\s*([A-Za-z_][\w\-\.:]*)\b', b[i:])
    if not m:
        last = b.rfind(b'>'); return last + 1 if last != -1 else len(b)
    root = m.group(1)
    pat = re.compile(br'</\s*' + re.escape(root) + br'\s*>')
    endm = None
    for endm in pat.finditer(b): pass
    if not endm:
        last = b.rfind(b'>'); return last + 1 if last != -1 else len(b)
    return endm.end()

# ---------- commands ----------
def decrypt(path_dat: str, out_xml: str = None):
    blob = open(path_dat, "rb").read()
    idx = blob.rfind(MAGIC)
    if idx == -1 or len(blob) - idx < FOOTER_LEN:
        dec = bxor(blob)
        end = find_xml_end(dec)
        xml = dec[:end]
        out_xml = out_xml or os.path.splitext(path_dat)[0] + "_decrypted.xml"
        open(out_xml, "wb").write(xml)
        print(f"OK: XML → {out_xml} (no CIGG found)")
        return

    payload_enc = blob[:idx]
    footer = blob[idx:idx+FOOTER_LEN]

    key = autodetect_key(payload_enc)
    dec = bxor(payload_enc, key)
    end = find_xml_end(dec)
    xml = dec[:end]

    out_xml = out_xml or os.path.splitext(path_dat)[0] + "_decrypted.xml"
    open(out_xml, "wb").write(xml)
    length_be = struct.unpack(">H", footer[6:8])[0]
    crc_be = footer[8:12]
    print(f"OK: XML → {out_xml}")
    print(f"ℹ XOR key=0x{key:02x}  payload_len(enc)={len(payload_enc)} (footer says {length_be})")
    print(f"ℹ footer CRC32/BZIP2={crc_be.hex()}  our CRC would be {crc32_bzip2_be(payload_enc).hex()}")

def encrypt(path_xml: str, out_dat: str = None, ensure_final_lf: bool = False):
    xml = open(path_xml, "rb").read()
    if ensure_final_lf and not xml.endswith(b"\n"):
        xml = xml + b"\n"

    payload_enc = bxor(xml, KEY)

    length_be = struct.pack(">H", len(payload_enc) & 0xFFFF)
    crc_be = crc32_bzip2_be(payload_enc)
    footer = MAGIC + b"\x00\x00" + length_be + crc_be + (b"\x11"*4) + (b"\x00"*16)

    out_dat = out_dat or os.path.splitext(path_xml)[0] + "_assembled.dat"
    open(out_dat, "wb").write(payload_enc + footer)
    print(f"OK: DAT → {out_dat}")
    print(f"ℹ footer = {footer.hex()} (lenBE={length_be.hex()} crcBE={crc_be.hex()})")

def help():
    print("""cig_config_tool_final.py
Usage:
  python cig_config_tool_final.py decrypt config.dat [out.xml]
  python cig_config_tool_final.py encrypt config_decrypted.xml [out.dat]
  # опция --lf добавит завершающий '\\n' если его нет
""")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        help(); sys.exit(0)
    cmd = sys.argv[1]
    if cmd == "decrypt":
        decrypt(sys.argv[2], sys.argv[3] if len(sys.argv)>3 else None)
    elif cmd == "encrypt":
        out = None; addlf = False; i = 3
        while i < len(sys.argv):
            a = sys.argv[i]
            if a == "-o" and i+1 < len(sys.argv): out = sys.argv[i+1]; i += 2; continue
            if a == "--lf": addlf = True; i += 1; continue
            i += 1
        encrypt(sys.argv[2], out, ensure_final_lf=addlf)
    else:
        help()
