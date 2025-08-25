# CIG Config Tool - MicroPython version
import struct
import re

from pyscript import window, ffi

MAGIC = b"CIGG"
FOOTER_LEN = 32
KEY = 0xAA

current_file = None
processed_data = None
processed_name = None


def log(msg):
    """Log message to console"""
    try:
        console = window.document.getElementById('console')
        import time
        timestamp = str(time.time())[-8:-2]
        console.textContent += f"[{timestamp}] {msg}\n"
        console.scrollTop = 999999
    except Exception as e:
        print(f"Log error: {e}")


def bxor(data, key=KEY):
    """XOR encryption/decryption"""
    return bytes([b ^ (key & 0xFF) for b in data])


def autodetect_key(enc):
    """Auto-detect XOR key"""
    if len(enc) >= 2:
        candidates = [enc[-2] ^ 0x3E, enc[-1] ^ 0x0A, enc[-2] ^ 0x0D]
        for k in candidates:
            test = bxor(enc[:min(4096, len(enc))], k)
            if b'<?xml' in test[:100]:
                return k
    
    for k in range(256):
        test = bxor(enc[:min(1024, len(enc))], k)
        if b'<?xml' in test[:50]:
            return k
    return KEY


def find_xml_end(data):
    """Find end of XML data"""
    if not data:
        return 0
    pos = data.rfind(b'>')
    return pos + 1 if pos != -1 else len(data)


def crc32_bzip2(data):
    """CRC32/BZIP2 calculation"""
    poly, crc = 0x04C11DB7, 0xFFFFFFFF
    
    for byte in data:
        crc ^= (byte << 24)
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ poly) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    
    return struct.pack(">I", crc ^ 0xFFFFFFFF)


def handle_file(file):
    """Handle uploaded file"""
    global current_file
    current_file = file
    log(f"📁 Файл загружен: {file.name}")


def process_file():
    """Process the uploaded file"""
    global processed_data, processed_name
    
    file = getattr(window, 'currentFile', None)
    if not file:
        log("❌ Нет файла для обработки")
        return
    
    file_name = file.name.lower()
    is_dat = file_name.endswith('.dat')
    is_xml = file_name.endswith('.xml')
    
    if not (is_dat or is_xml):
        log("❌ Поддерживаются только .dat и .xml файлы")
        return
    
    log(f"🔄 Обрабатываю: {file.name}")
    
    def handle_file_data(array_buffer):
        global processed_data, processed_name
        
        try:
            uint8_array = window.Uint8Array.new(array_buffer)
            array_length = uint8_array.length
            log(f"📊 Размер: {array_length} bytes")
            
            data_bytes = bytes([uint8_array[i] for i in range(array_length)])
            log("✅ Конвертация завершена")
            
            if is_dat:
                idx = data_bytes.rfind(MAGIC)
                
                if idx == -1:
                    decrypted = bxor(data_bytes)
                    log("ℹ️ Нет CIGG футера, простой XOR")
                else:
                    payload = data_bytes[:idx]
                    key = autodetect_key(payload)
                    decrypted = bxor(payload, key)
                    log(f"ℹ️ XOR key=0x{key:02X}")
                
                xml_data = decrypted[:find_xml_end(decrypted)]
                processed_data = xml_data
                processed_name = file.name.rsplit('.', 1)[0] + "_decrypted.xml"
                log("✅ Расшифровано")
                
            else:
                xml_data = data_bytes
                
                if window.document.getElementById('addLF').checked and not xml_data.endswith(b"\n"):
                    xml_data += b"\n"
                    log("ℹ️ Добавлен LF")
                
                payload = bxor(xml_data, KEY)
                length_be = struct.pack(">H", len(payload) & 0xFFFF)
                crc_be = crc32_bzip2(payload)
                footer = MAGIC + b"\x00\x00" + length_be + crc_be + b"\x11"*4 + b"\x00"*16
                
                processed_data = payload + footer
                processed_name = file.name.rsplit('.', 1)[0] + "_encrypted.dat"
                log("✅ Зашифровано")
            
            window.document.getElementById('downloadCard').style.display = 'block'
            
        except Exception as e:
            log(f"❌ Ошибка: {e}")
    
    reader = window.FileReader.new()
    reader.onload = ffi.create_proxy(lambda e: handle_file_data(e.target.result))
    reader.readAsArrayBuffer(file)


def download_file():
    """Download processed file"""
    if not processed_data or not processed_name:
        log("❌ Нет данных для скачивания")
        return
    
    try:
        uint8_array = window.Uint8Array.new(processed_data)
        blob = window.Blob.new([uint8_array], {"type": "application/octet-stream"})
        url = window.URL.createObjectURL(blob)
        
        link = window.document.createElement('a')
        link.href = url
        link.download = processed_name
        window.document.body.appendChild(link)
        link.click()
        window.document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
        
        log(f"📥 Скачан: {processed_name}")
    except Exception as e:
        log(f"❌ Ошибка скачивания: {e}")


def clear_console():
    """Clear console"""
    try:
        window.document.getElementById('console').textContent = ''
    except Exception as e:
        log(f"❌ Ошибка: {e}")


def setup_ui():
    """Setup UI event handlers"""
    try:
        window.document.getElementById('processBtn').onclick = ffi.create_proxy(lambda e: process_file())
        window.document.getElementById('downloadBtn').onclick = ffi.create_proxy(lambda e: download_file())
        window.document.getElementById('clearBtn').onclick = ffi.create_proxy(lambda e: clear_console())
        
        window.pyHandleFile = ffi.create_proxy(handle_file)
        
        log("🚀 MicroPython готов")
        
    except Exception as e:
        print(f"Setup error: {e}")

try:
    setup_ui()
except Exception as e:
    print(f"Init error: {e}")