import ctypes
import os
import shutil
import subprocess
from pathlib import Path


class Fast_Crypto_Bridge:
    def __init__(self):
        self.dll = None
        self.is_ready = False
        self._init_engine()

    def _init_engine(self):
        base_dir = Path(__file__).resolve().parent.parent / "c_src"
        dll_path = base_dir / "pkt_fast_crypto.dll"
        c_file = base_dir / "pkt_fast_crypto.c"
        twofish_c = base_dir / "twofish.c"

        if not dll_path.exists():
            gcc_path = shutil.which("gcc")
            if not gcc_path:
                return

            compile_cmd = [
                gcc_path,
                "-O3",
                "-shared",
                "-o",
                str(dll_path),
                str(c_file),
                str(twofish_c),
                "-I",
                str(base_dir),
            ]
            res = subprocess.run(compile_cmd, capture_output=True, text=True)
            if res.returncode != 0 or not dll_path.exists():
                return

        try:
            self.dll = ctypes.CDLL(str(dll_path))
            self._setup_signatures()
            self.is_ready = True
        except Exception:
            self.is_ready = False

    def _setup_signatures(self):
        self.dll.fast_decrypt_pkt.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.dll.fast_decrypt_pkt.restype = ctypes.c_int

        self.dll.fast_encrypt_pkt.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.dll.fast_encrypt_pkt.restype = ctypes.c_int

    def decrypt(self, in_data: bytes, key: bytes, iv: bytes) -> bytes:
        if not self.is_ready:
            raise RuntimeError("Fast C crypto bridge is not available.")

        in_len = len(in_data)
        out_buf = ctypes.create_string_buffer(in_len)
        out_len = ctypes.c_size_t()

        ret = self.dll.fast_decrypt_pkt(
            in_data,
            in_len,
            key,
            iv,
            out_buf,
            ctypes.byref(out_len),
        )

        if ret != 0:
            raise ValueError(f"Fast C decryption failed with status code {ret}")

        return out_buf.raw[:out_len.value]

    def encrypt(self, in_data: bytes, key: bytes, iv: bytes) -> bytes:
        if not self.is_ready:
            raise RuntimeError("Fast C crypto bridge is not available.")

        in_len = len(in_data)
        out_buf = ctypes.create_string_buffer(in_len + 16)
        out_len = ctypes.c_size_t()

        ret = self.dll.fast_encrypt_pkt(
            in_data,
            in_len,
            key,
            iv,
            out_buf,
            ctypes.byref(out_len),
        )

        if ret != 0:
            raise ValueError(f"Fast C encryption failed with status code {ret}")

        return out_buf.raw[:out_len.value]
