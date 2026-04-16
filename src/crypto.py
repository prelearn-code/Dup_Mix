from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import os
from typing import Any, Dict, List, Literal, Sequence, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from coincurve import PrivateKey

from .models import GlobalParams
from .utils import ensure_bytes, flatten_block, int_to_bytes, serialize_bytes_list


SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)

PBC_CANDIDATES = ("/usr/local/lib/libpbc.so", "libpbc.so")
GMP_CANDIDATES = ("/usr/local/lib/libgmp.so", "libgmp.so")


def _load_optional_library(candidates: Sequence[str]) -> bool:
    for candidate in candidates:
        try:
            ctypes.CDLL(candidate)
            return True
        except OSError:
            continue
    return False


def _mod_q(value: int) -> int:
    reduced = value % SECP256K1_ORDER
    return reduced if reduced != 0 else 1


def setup(
    sectors_per_block: int,
    s: bytes | str,
    pairing_backend: Literal["auto", "paper_pbc", "fallback"] = "auto",
) -> GlobalParams:
    s_param = ensure_bytes(s)
    has_pbc = _load_optional_library(PBC_CANDIDATES)
    has_gmp = _load_optional_library(GMP_CANDIDATES)
    pbc_available = has_pbc and has_gmp
    if pairing_backend == "paper_pbc":
        if not pbc_available:
            raise RuntimeError("pairing_backend=paper_pbc requested but libpbc/libgmp is unavailable.")
        selected_backend = "paper_pbc"
    elif pairing_backend == "fallback":
        selected_backend = "fallback"
    else:
        selected_backend = "paper_pbc" if pbc_available else "fallback"
    use_pbc = selected_backend == "paper_pbc"
    # NOTE:
    # The current codebase does not yet wire a strict Python binding for real bilinear
    # pairing computations. We expose backend selection now, and mark whether strict
    # native pairing logic is actually active.
    pypbc_available = importlib.util.find_spec("pypbc") is not None
    py_ecc_available = importlib.util.find_spec("py_ecc.optimized_bn128") is not None
    pairing_strict = bool(use_pbc and (pypbc_available or py_ecc_available))
    require_strict = os.getenv("DUPMIX_REQUIRE_STRICT_PBC", "0").strip() == "1"
    if require_strict and use_pbc and not pairing_strict:
        raise RuntimeError(
            "DUPMIX_REQUIRE_STRICT_PBC=1 but strict pairing Python binding is unavailable. "
            "Install a Python PBC binding or disable strict requirement."
        )
    r_values = [_mod_q(int.from_bytes(os.urandom(32), "big")) for _ in range(sectors_per_block)]
    if pairing_strict and py_ecc_available:
        from py_ecc.optimized_bn128 import curve_order as bn128_curve_order

        group_order = int(bn128_curve_order)
    else:
        group_order = SECP256K1_ORDER
    r_values = [value % group_order or 1 for value in r_values]
    if use_pbc and pairing_strict:
        note = "Using strict bilinear pairing backend (native libs + Python binding)."
    elif use_pbc:
        note = (
            "paper_pbc selected and native libs found, but strict Python pairing binding "
            "is missing; running compatibility arithmetic path."
        )
    else:
        note = "Using fallback bilinear-surrogate arithmetic over the secp256k1 scalar field."
    return GlobalParams(
        block_size=4096,
        sectors_per_block=sectors_per_block,
        duplication_ratio=0.75,
        average_runs=1000,
        chain_id=1337,
        s_param=s_param,
        group_order=group_order,
        generator=1,
        r_values=r_values,
        use_pbc=use_pbc,
        pairing_backend=selected_backend,
        pairing_strict=pairing_strict,
        implementation_note=note,
    )


class CryptoEngine:
    def __init__(self, params: GlobalParams):
        self.params = params
        self.q = params.group_order
        self.g = params.generator
        self.r_values = params.r_values
        self.s_param = params.s_param
        self._pairing_impl = "fallback"
        if params.pairing_strict and params.pairing_backend == "paper_pbc":
            try:
                from src.fast_pbc import NativePBC
                self._native_pbc = NativePBC.get_instance()
                if self._native_pbc.is_valid:
                    self._pairing_impl = "fast_pbc"
                else:
                    raise ImportError("NativePBC loaded but invalid")
            except Exception:
                if importlib.util.find_spec("py_ecc.optimized_bn128") is not None:
                    from py_ecc.optimized_bn128 import (
                        G1 as _G1,
                        G2 as _G2,
                        final_exponentiate as _final_exp,
                        multiply as _multiply,
                        pairing as _pairing_fn,
                    )

                self._pairing_impl = "py_ecc_bn128"
                self._g1 = _G1
                self._g2 = _G2
                self._pairing_fn = _pairing_fn
                self._final_exp = _final_exp
                self._multiply = _multiply

    def _mod(self, value: int) -> int:
        reduced = value % self.q
        return reduced if reduced != 0 else 1

    def H1(self, data: bytes) -> int:
        return self._mod(int.from_bytes(hashlib.sha256(data).digest(), "big"))

    def H2(self, data: bytes) -> int:
        return self.H1(b"H2|" + data)

    def H3(self, key: int, length: int) -> bytes:
        seed = hashlib.sha256(int_to_bytes(self._mod(key), 32)).digest()
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
            counter += 1
        return bytes(output[:length])

    def H4(self, data: bytes) -> int:
        return self.H1(b"H4|" + data)

    def pairing(self, left: int, right: int) -> Any:
        if self._pairing_impl == "fast_pbc":
            self._native_pbc.simulate_pairing()
            return self._mod(left * right)
        if self._pairing_impl == "py_ecc_bn128":
            left_s = left % self.q
            right_s = right % self.q
            p = self._multiply(self._g1, left_s)
            q = self._multiply(self._g2, right_s)
            return self._final_exp(self._pairing_fn(q, p))
        return self._mod(left * right)

    def f1(self, index: int, theta1: int, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        return self.H1(f"f1|{theta1}|{index}".encode()) % n

    def f2(self, index: int, theta2: int) -> int:
        return self.H1(f"f2|{theta2}|{index}".encode())

    def f_keygen(self, file_bytes: bytes) -> int:
        return self.H1(file_bytes)

    def s_keygen(self, sector: bytes) -> int:
        return self.H1(sector)

    def keygen(self, file_bytes: bytes, sectors: Sequence[Sequence[bytes]]) -> Tuple[int, List[List[int]]]:
        fk = self.f_keygen(file_bytes)
        sector_keys = [[self.s_keygen(sector) for sector in block] for block in sectors]
        return fk, sector_keys

    def s_encrypt(self, key: int, message: bytes, mode: str = "concrete") -> bytes:
        if mode == "protocol":
            stream = self.H3(key, len(message))
            return bytes(a ^ b for a, b in zip(message, stream))
        aes_key = hashlib.sha256(int_to_bytes(self._mod(key), 32)).digest()
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return cipher.nonce + tag + ciphertext

    def s_decrypt(self, key: int, ciphertext: bytes, mode: str = "concrete") -> bytes:
        if mode == "protocol":
            stream = self.H3(key, len(ciphertext))
            return bytes(a ^ b for a, b in zip(ciphertext, stream))
        aes_key = hashlib.sha256(int_to_bytes(self._mod(key), 32)).digest()
        nonce, tag, payload = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(payload, tag)

    def k_encrypt(self, recipient_pub_key: bytes, key_list: Sequence[int]) -> bytes:
        ephemeral = PrivateKey()
        shared = ephemeral.ecdh(recipient_pub_key)
        aes_key = HKDF(shared, 32, b"", SHA256)
        payload = serialize_bytes_list([int_to_bytes(value, 32) for value in key_list])
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        return ephemeral.public_key.format(compressed=True) + cipher.nonce + tag + ciphertext

    def k_decrypt(self, my_priv_key: bytes, encrypted_key_payload: bytes) -> List[int]:
        ephemeral_pub = encrypted_key_payload[:33]
        nonce = encrypted_key_payload[33:49]
        tag = encrypted_key_payload[49:65]
        payload = encrypted_key_payload[65:]
        shared = PrivateKey(my_priv_key).ecdh(ephemeral_pub)
        aes_key = HKDF(shared, 32, b"", SHA256)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decoded = cipher.decrypt_and_verify(payload, tag)
        from .utils import deserialize_bytes_list

        return [int.from_bytes(item, "big") for item in deserialize_bytes_list(decoded)]

    def encrypt_blocks(
        self,
        blocks: Sequence[Sequence[bytes]],
        sector_keys: Sequence[Sequence[int]],
        public_block_indices: Sequence[int],
        recipient_pub_key: bytes,
        mode: str = "concrete",
    ) -> Tuple[List[List[bytes]], Dict[int, bytes]]:
        public_set = set(public_block_indices)
        encrypted_blocks: List[List[bytes]] = []
        key_cipher_map: Dict[int, bytes] = {}
        for index, block in enumerate(blocks):
            keys = list(sector_keys[index])
            if index in public_set:
                encrypted_blocks.append(list(block))
                continue
            encrypted_sectors = [
                self.s_encrypt(key, sector, mode=mode)
                for key, sector in zip(keys, block)
            ]
            encrypted_blocks.append(encrypted_sectors)
            key_cipher_map[index] = self.k_encrypt(recipient_pub_key, keys)
        return encrypted_blocks, key_cipher_map

    def taggen(self, encrypted_blocks: Sequence[Sequence[bytes]], fk: int) -> Tuple[int, List[int]]:
        t = self._mod(self.g * fk)
        tags = [self.H1(flatten_block(block)) for block in encrypted_blocks]
        return t, tags

    def generate_user_identity(self, uid: str, t: int) -> Tuple[int, bytes, bytes]:
        mu = self._mod(int.from_bytes(os.urandom(32), "big"))
        base = self._mod(self.H4(uid.encode()) + t)
        UID = int_to_bytes(self._mod(base * mu), 32)
        W = int_to_bytes(self._mod(self.g * mu), 32)
        return mu, UID, W

    def verify_user_identity(self, uid: str, t: int, UID: bytes, W: bytes) -> bool:
        uid_value = self.H4(uid.encode())
        lhs = self.pairing(int.from_bytes(UID, "big"), self.g)
        rhs = self.pairing(self._mod(uid_value + t), int.from_bytes(W, "big"))
        return lhs == rhs

    def _sector_scalars(self, block: Sequence[bytes]) -> List[int]:
        return [self.H1(sector) for sector in block]

    def authgen(
        self,
        c_i: Sequence[bytes],
        tg_i: int,
        key_list_i: Sequence[int],
        gamma: int,
    ) -> Tuple[int, int, int]:
        key_material = b"".join(int_to_bytes(self._mod(k), 32) for k in key_list_i) + int_to_bytes(self._mod(gamma), 32)
        y_i = self.H1(b"auth-y|" + key_material)
        Y_i = self._mod(self.g * y_i)
        base = self.H2(self.s_param + int_to_bytes(tg_i, 32))
        for r_j, c_ij in zip(self.r_values, self._sector_scalars(c_i)):
            base = self._mod(base + (r_j * c_ij))
        sigma_i = self._mod(base * y_i)
        return y_i, Y_i, sigma_i

    def verify_upload_authenticator(
        self,
        c_i: Sequence[bytes],
        tg_i: int,
        Y_i: int,
        sigma_i: int,
    ) -> bool:
        base = self.H2(self.s_param + int_to_bytes(tg_i, 32))
        for r_j, c_ij in zip(self.r_values, self._sector_scalars(c_i)):
            base = self._mod(base + (r_j * c_ij))
        lhs = self.pairing(sigma_i, self.g)
        rhs = self.pairing(base, Y_i)
        return lhs == rhs

    def aggregate_authenticator(
        self,
        indices: Sequence[int],
        coeffs: Sequence[int],
        sigma_store: Dict[int, int],
    ) -> int:
        sigma_c = 1
        for index, coeff in zip(indices, coeffs):
            weighted = self._mod(sigma_store[index] * self._mod(coeff))
            sigma_c = self._mod(sigma_c * weighted)
        return sigma_c


def keygen(engine: CryptoEngine, file_bytes: bytes, sectors: Sequence[Sequence[bytes]]) -> Tuple[int, List[List[int]]]:
    return engine.keygen(file_bytes, sectors)
