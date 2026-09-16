import struct
import zlib
from typing import Tuple

from pktcore.crypto.c_bridge import Fast_Crypto_Bridge
from pktcore.crypto.eax_py import EAX
from pktcore.crypto.twofish_py import Twofish

DEFAULT_PKT_KEY = bytes([137]) * 16
DEFAULT_PKT_IV = bytes([16]) * 16
LEGACY_ZLIB_WBITS = (15, -15, 31)


def deobf_stage1(data: bytes) -> bytes:
    data_len = len(data)
    return bytes(data[data_len - 1 - i] ^ ((data_len - i * data_len) & 0xFF) for i in range(data_len))


def obf_stage1(data: bytes) -> bytes:
    data_len = len(data)
    output = bytearray(data_len)

    for i in range(data_len):
        key_byte = (data_len - i * data_len) & 0xFF
        output[data_len - 1 - i] = data[i] ^ key_byte

    return bytes(output)


def deobf_stage2(data: bytes) -> bytes:
    data_len = len(data)
    return bytes(b ^ ((data_len - i) & 0xFF) for i, b in enumerate(data))


def obf_stage2(data: bytes) -> bytes:
    data_len = len(data)
    return bytes(b ^ ((data_len - i) & 0xFF) for i, b in enumerate(data))


def uncompress_qt(blob: bytes) -> bytes:
    size = struct.unpack(">I", blob[:4])[0]
    return zlib.decompress(blob[4:])[:size]


def compress_qt(xml_data: bytes) -> bytes:
    size_header = struct.pack(">I", len(xml_data))
    compressed_body = zlib.compress(xml_data)
    return size_header + compressed_body


def legacy_xor_schedule(data: bytes) -> bytes:
    size = len(data)
    out = bytearray()

    for byte in data:
        out.append((byte ^ size) & 0xFF)
        size -= 1

    return bytes(out)


def try_legacy_decompile(data: bytes) -> bytes:
    out = legacy_xor_schedule(data)

    for wbits in LEGACY_ZLIB_WBITS:
        try:
            return zlib.decompress(out[4:], wbits=wbits)
        except zlib.error:
            continue

    raise ValueError("Legacy XOR wrapper decompression failed")


class Pkt_Pipeline:
    def __init__(self, key: bytes = DEFAULT_PKT_KEY, iv: bytes = DEFAULT_PKT_IV):
        self.key = key
        self.iv = iv
        self.c_bridge = Fast_Crypto_Bridge()

    def decompile(self, pkt_bytes: bytes) -> bytes:
        if self.c_bridge.is_ready:
            try:
                stage2_bytes = self.c_bridge.decrypt(pkt_bytes, self.key, self.iv)
                return uncompress_qt(stage2_bytes)
            except Exception:
                pass

        try:
            stage1 = deobf_stage1(pkt_bytes)
            tf = Twofish(self.key)
            eax = EAX(tf.encrypt)

            ciphertext = stage1[:-16]
            tag = stage1[-16:]
            decrypted = eax.decrypt(nonce=self.iv, ciphertext=ciphertext, tag=tag)

            stage2 = deobf_stage2(decrypted)
            return uncompress_qt(stage2)
        except Exception:
            pass

        return try_legacy_decompile(pkt_bytes)

    def compile(self, xml_bytes: bytes) -> bytes:
        compressed = compress_qt(xml_bytes)

        if self.c_bridge.is_ready:
            try:
                return self.c_bridge.encrypt(compressed, self.key, self.iv)
            except Exception:
                pass

        stage2_blob = obf_stage2(compressed)
        tf = Twofish(self.key)
        eax = EAX(tf.encrypt)

        ciphertext, tag = eax.encrypt(nonce=self.iv, plaintext=stage2_blob)
        stage1_input = ciphertext + tag

        return obf_stage1(stage1_input)
