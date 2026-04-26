from __future__ import annotations

import ctypes
import os
import subprocess
from uuid import uuid4
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "pbc_pairing_wrapper.c"
LIB = ROOT / "src" / "libpbc_pairing_wrapper.so"


class PBCPairing:
    """Python 侧 PBC pairing 封装。

    作用：把项目中的指数表示 g^a/g^b 转交给 C wrapper，
    由 C/PBC 构造真实 G1/G2/GT 元素并执行 pairing_apply。
    """

    def __init__(self) -> None:
        self._ensure_compiled()
        try:
            self.lib = ctypes.CDLL(str(LIB))
        except OSError:
            LIB.unlink(missing_ok=True)
            self._ensure_compiled()
            self.lib = ctypes.CDLL(str(LIB))
        self.lib.pbc_pairing_check_equal.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self.lib.pbc_pairing_check_equal.restype = ctypes.c_int
        self.lib.pbc_pairing_check_product.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_int,
        ]
        self.lib.pbc_pairing_check_product.restype = ctypes.c_int

    @staticmethod
    def _ensure_compiled() -> None:
        if LIB.exists() and LIB.stat().st_mtime >= SRC.stat().st_mtime:
            return
        tmp_lib = LIB.with_name(f"{LIB.name}.{os.getpid()}.{uuid4().hex}.tmp")
        cmd = [
            "gcc",
            "-shared",
            "-fPIC",
            str(SRC),
            "-I/usr/local/include",
            "-L/usr/local/lib",
            "-lpbc",
            "-lgmp",
            "-o",
            str(tmp_lib),
        ]
        try:
            subprocess.run(cmd, check=True, cwd=str(ROOT))
            os.replace(tmp_lib, LIB)
        finally:
            tmp_lib.unlink(missing_ok=True)

    @staticmethod
    def _b(value: int) -> bytes:
        return str(int(value)).encode()

    def equal(self, left_a: int, left_b: int, right_a: int, right_b: int) -> bool:
        """验证基础 pairing 等式：e(g^left_a,g^left_b)==e(g^right_a,g^right_b)。"""
        return bool(
            self.lib.pbc_pairing_check_equal(
                self._b(left_a),
                self._b(left_b),
                self._b(right_a),
                self._b(right_b),
            )
        )

    def product_equal(
        self,
        left_exp: int,
        bases: Sequence[int],
        ys: Sequence[int],
        coeffs: Sequence[int],
    ) -> bool:
        """验证审计公式：e(g^left_exp,g)==prod_i e(g^base_i,g^Y_i)^{v_i}。"""
        if not (len(bases) == len(ys) == len(coeffs)):
            raise ValueError("bases, ys, and coeffs must have the same length")
        count = len(bases)
        array_type = ctypes.c_char_p * count
        base_array = array_type(*(self._b(value) for value in bases))
        y_array = array_type(*(self._b(value) for value in ys))
        coeff_array = array_type(*(self._b(value) for value in coeffs))
        return bool(
            self.lib.pbc_pairing_check_product(
                self._b(left_exp),
                base_array,
                y_array,
                coeff_array,
                ctypes.c_int(count),
            )
        )
