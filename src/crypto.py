from __future__ import annotations

import ctypes
import hmac
import hashlib
import os
from typing import Dict, List, Sequence, Tuple

from coincurve import PrivateKey

from .models import GlobalParams
from .pbc_pairing import PBCPairing
from .utils import deserialize_bytes_list, ensure_bytes, flatten_block, int_to_bytes, serialize_bytes_list


# 初始化群参数
SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)

# G_1的阶数，PBC Type-A pairing的群阶，就是大素数p
PBC_TYPE_A_ORDER = 730750818665451621361119245571504901405976559617

# 导入libpbc和libgmp的候选路径
PBC_CANDIDATES = ("/usr/local/lib/libpbc.so", "libpbc.so")
GMP_CANDIDATES = ("/usr/local/lib/libgmp.so", "libgmp.so")


# 尝试加载可选的库，返回是否成功
def _load_optional_library(candidates: Sequence[str]) -> bool:
    for candidate in candidates:
        try:
            ctypes.CDLL(candidate)
            return True
        except OSError:
            continue
    return False


# 将整数值映射到1到PBC_TYPE_A_ORDER-1的范围内，确保不为0
def _mod_q(value: int) -> int:
    reduced = value % PBC_TYPE_A_ORDER
    return reduced if reduced != 0 else 1


# 设置全局参数，确保使用PBC Type-A pairing，并生成随机r_j值
# sectors_per_block: 每个块中的扇区数量
# s: 用于H2函数的全局参数，可以是字节串或字符串,最终用到H2函数中，
# 确保在认证生成和验证过程中保持一致


def setup(
    sectors_per_block: int,
    s: bytes | str,
) -> GlobalParams:
    """Setup 算法：生成全局参数 p, g, e, s, R={r_j}。

    论文对应系统初始化阶段。本实现中群元素用 Type-A 群阶上的指数表示，
    但 pairing 等式验证会调用本地 C/PBC pairing_apply。
    """
    s_param = ensure_bytes(s)
    has_pbc = _load_optional_library(PBC_CANDIDATES)
    has_gmp = _load_optional_library(GMP_CANDIDATES)
    pbc_available = has_pbc and has_gmp
    if not pbc_available:
        raise RuntimeError("Strict paper reproduction requires libpbc/libgmp.")
    use_pbc = True
    pairing_strict = True

    # 由 s 派生稳定的 R={r_j}。持久化 CSP DB 会跨进程复用 HVT，
    # 因此同一系统参数下的 r_j 必须可复现。
    r_values = [
        _mod_q(int.from_bytes(hashlib.sha256(b"setup-r|" + s_param + int_to_bytes(index, 4)).digest(), "big"))
        for index in range(sectors_per_block)
    ]
    group_order = PBC_TYPE_A_ORDER
    r_values = [value % group_order or 1 for value in r_values]
    note = (
        "Using strict paper PBC Type-A native pairing checks. "
        "Group elements are represented by exponents modulo the Type-A group order; "
        "pairing equality is verified through local C/PBC pairing_apply."
    )
    return GlobalParams(
        block_size=4096,
        sectors_per_block=sectors_per_block,
        duplication_ratio=0.75,
        average_runs=1000,
        chain_id=1337,
        s_param=s_param, # 用于H2函数的全局参数
        group_order=group_order,
        generator=1, # 在PBC Type-A pairing中，生成元g可以表示为1，因为我们使用指数表示法
        r_values=r_values,
        use_pbc=use_pbc,
        pairing_backend="paper_pbc",
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
        if not params.pairing_strict or params.pairing_backend != "paper_pbc":
            raise RuntimeError("CryptoEngine only supports strict paper_pbc mode.")
        self.native_pairing = PBCPairing()

    def _mod(self, value: int) -> int:
        reduced = value % self.q
        return reduced if reduced != 0 else 1
    
    # sha256哈希函数，返回整数值，并确保结果在1到q-1的范围内，以满足认证生成和验证的要求
    def H1(self, data: bytes) -> int:
        """H1: {0,1}* -> Z_p，用于 fk=H1(F)、k_i,j=H1(m_i,j)、tg_i=H1(c_i)。"""
        return self._mod(int.from_bytes(hashlib.sha256(data).digest(), "big"))
    
    #H2实现
    def H2(self, data: bytes) -> int:
        """H2: {0,1}* -> G1 的指数表示，用于 AuthGen 中 H2(s||tg_i)。"""
        return self.H1(b"H2|" + data)
    
    # H3实现，使用SHA-256作为伪随机函数，生成足够长度的字节流，并确保输出长度满足要求
    def H3(self, key: int, length: int) -> bytes:
        """H3: Z_p -> {0,1}^l，用于私有 sector 加密 c_i,j=H3(k_i,j) xor m_i,j。"""
        seed = hashlib.sha256(int_to_bytes(self._mod(key), 32)).digest()
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
            counter += 1
        return bytes(output[:length])

    def H4(self, data: bytes) -> int:
        """H4: uid -> G1 的指数表示，用于用户身份公式 UID=(H4(uid)*t)^mu。"""
        return self.H1(b"H4|" + data)
    
    # 论文双线性性质 e(g^a,g^b)=e(g,g)^(ab) 的指数记录形式。
    # 该函数只用于 proof payload 中记录 pairing 指数；真正验证调用 pairing_equal / pairing_product_equal。
    def pairing_exponent(self, left: int, right: int) -> int:
        return self._mod(left * right)

    # 论文身份验证与上传认证器验证中的基础等式：
    # e(g^left_a, g^left_b) == e(g^right_a, g^right_b)。
    # 这里调用本地 C/PBC pairing_apply 比较真实 GT 元素。
    def pairing_equal(self, left_a: int, left_b: int, right_a: int, right_b: int) -> bool:
        return self.native_pairing.equal(
            self._mod(left_a),
            self._mod(left_b),
            self._mod(right_a),
            self._mod(right_b),
        )

    # 论文审计验证公式：
    # e(sigma_c, g) == prod_i e(base_i, Y_i)^{v_i}。
    # bases 对应 H2(s||tg_i)*prod_j r_j^{c_i,j} 的指数表示，ys 对应 Y_i，coeffs 对应 v_i。
    def pairing_product_equal(
        self,
        left_exp: int,
        bases: Sequence[int],
        ys: Sequence[int],
        coeffs: Sequence[int],
    ) -> bool:
        return self.native_pairing.product_equal(
            self._mod(left_exp),
            [self._mod(value) for value in bases],
            [self._mod(value) for value in ys],
            [self._mod(value) for value in coeffs],
        )

    def f1(self, index: int, theta1: int, n: int) -> int:
        """f1: 审计挑战索引生成函数，用 theta1 选择被挑战块 x_i。"""
        if n <= 0:
            raise ValueError("n must be positive")
        return self.H1(f"f1|{theta1}|{index}".encode()) % n

    def f2(self, index: int, theta2: int) -> int:
        """f2: 审计挑战系数生成函数，用 theta2 生成 v_i。"""
        return self.H1(f"f2|{theta2}|{index}".encode())
    
    # 文件密钥生成
    def f_keygen(self, file_bytes: bytes) -> int:
        """KeyGen 文件密钥公式：fk=H1(F)。"""
        return self.H1(file_bytes)
    
    # 扇区密钥生成
    def s_keygen(self, sector: bytes) -> int:
        """KeyGen sector 密钥公式：k_i,j=H1(m_i,j)。"""
        return self.H1(sector)
    
    # 生成文件密钥和扇区密钥列表，用于后续的加密和认证过程，生成密钥集合，对应KEYS集合
    def keygen(self, file_bytes: bytes, sectors: Sequence[Sequence[bytes]]) -> Tuple[int, List[List[int]]]:
        """KeyGen 集成步骤：输出 fk 与所有 sector keys K={k_i,j}。"""
        fk = self.f_keygen(file_bytes)
        sector_keys = [[self.s_keygen(sector) for sector in block] for block in sectors]
        return fk, sector_keys
    
    # 使用流密码方式加密扇区数据，生成伪随机流，并对扇区数据进行异或操作，确保加密和解密过程对称
    def s_encrypt(self, key: int, message: bytes) -> bytes:
        """Encrypt 私有 sector 公式：c_i,j=H3(k_i,j) xor m_i,j。"""
        stream = self.H3(key, len(message))
        return bytes(a ^ b for a, b in zip(message, stream))
    
    # 解密过程与加密对称，使用相同的密钥和伪随机流对密文进行异或操作，恢复原始扇区数据
    def s_decrypt(self, key: int, ciphertext: bytes) -> bytes:
        """Decrypt 私有 sector 公式：m_i,j=H3(k_i,j) xor c_i,j。"""
        stream = self.H3(key, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, stream))
    
    # 使用ECC-KEM方式加密文件密钥，生成临时密钥对，计算共享密钥，使用H1派生流密钥，对文件密钥列表进行加密，并生成认证标签，确保加密过程的安全性和完整性
    def k_encrypt(self, recipient_pub_key: bytes, key_list: Sequence[int]) -> bytes:
        """Key encapsulation：用接收方 ECC 公钥封装 private block 的 {k_i,j}。"""
        ephemeral = PrivateKey()
        shared = ephemeral.ecdh(recipient_pub_key)
        stream_key = self.H1(b"ECC-KEM|" + shared)
        payload = serialize_bytes_list([int_to_bytes(value, 32) for value in key_list])
        stream = self.H3(stream_key, len(payload))
        ciphertext = bytes(a ^ b for a, b in zip(payload, stream))
        tag = hashlib.sha256(b"ECC-KEM-TAG|" + shared + ciphertext).digest()
        return ephemeral.public_key.format(compressed=True) + tag + ciphertext

    def k_decrypt(self, my_priv_key: bytes, encrypted_key_payload: bytes) -> List[int]:
        """Key decapsulation：用用户 ECC 私钥恢复 private block 的 {k_i,j}。"""
        ephemeral_pub = encrypted_key_payload[:33]
        tag = encrypted_key_payload[33:65]
        ciphertext = encrypted_key_payload[65:]
        shared = PrivateKey(my_priv_key).ecdh(ephemeral_pub)
        expected_tag = hashlib.sha256(b"ECC-KEM-TAG|" + shared + ciphertext).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise PermissionError("Invalid key payload tag.")
        stream_key = self.H1(b"ECC-KEM|" + shared)
        stream = self.H3(stream_key, len(ciphertext))
        decoded = bytes(a ^ b for a, b in zip(ciphertext, stream))
        return [int.from_bytes(item, "big") for item in deserialize_bytes_list(decoded)]

    def encrypt_blocks(
        self,
        blocks: Sequence[Sequence[bytes]],
        sector_keys: Sequence[Sequence[int]],
        public_block_indices: Sequence[int],
        recipient_pub_key: bytes,
    ) -> Tuple[List[List[bytes]], Dict[int, bytes]]:
        """Mixed encryption：public block 明文保存，private block 按 sector 执行 H3 xor 并封装 keys。"""
        public_set = set(public_block_indices)
        encrypted_blocks: List[List[bytes]] = []
        key_cipher_map: Dict[int, bytes] = {}
        for index, block in enumerate(blocks):
            keys = list(sector_keys[index])
            if index in public_set:
                encrypted_blocks.append(list(block))
                continue
            encrypted_sectors = [
                self.s_encrypt(key, sector)
                for key, sector in zip(keys, block)
            ]
            encrypted_blocks.append(encrypted_sectors)
            key_cipher_map[index] = self.k_encrypt(recipient_pub_key, keys)
        return encrypted_blocks, key_cipher_map

    def taggen(self, encrypted_blocks: Sequence[Sequence[bytes]], fk: int) -> Tuple[int, List[int]]:
        """TagGen 公式：文件 tag t=g^fk，块 tag tg_i=H1(c_i)。"""
        t = self._mod(self.g * fk)
        tags = [self.H1(flatten_block(block)) for block in encrypted_blocks]
        return t, tags
    
    # 生成用户相关配对信息
    def generate_user_identity(self, uid: str, t: int) -> Tuple[int, bytes, bytes]:
        """用户身份生成公式：UID=(H4(uid)*t)^mu，W=g^mu。"""
        mu = self._mod(int.from_bytes(os.urandom(32), "big"))
        base = self._mod(self.H4(uid.encode()) + t)
        UID = int_to_bytes(self._mod(base * mu), 32)
        W = int_to_bytes(self._mod(self.g * mu), 32)
        return mu, UID, W
    

    # CSP验证用户身份公式：e(UID,g)==e(H4(uid)*t,W)
    def verify_user_identity(self, uid: str, t: int, UID: bytes, W: bytes) -> bool:
        uid_value = self.H4(uid.encode())
        return self.pairing_equal(
            int.from_bytes(UID, "big"),
            self.g,
            self._mod(uid_value + t),
            int.from_bytes(W, "big"),
        )
    
    
    def _sector_scalars(self, block: Sequence[bytes]) -> List[int]:
        """将 sector 映射到 Z_p，用于 AuthGen 中 prod_j r_j^{c_i,j} 的指数计算。"""
        return [self.H1(sector) for sector in block]

    def authgen(
        self,
        c_i: Sequence[bytes],
        tg_i: int,
        key_list_i: Sequence[int],
        gamma: int,
    ) -> Tuple[int, int, int]:
        """AuthGen 公式：y_i=(sum_j k_i,j) xor gamma，Y_i=g^{y_i}，
        sigma_i=(H2(s||tg_i)*prod_j r_j^{c_i,j})^{y_i}。
        """
        y_i = self._mod(sum(self._mod(k) for k in key_list_i) ^ self._mod(gamma))
        Y_i = self._mod(self.g * y_i)
        base = self.H2(self.s_param + int_to_bytes(tg_i, 32))
        for r_j, c_ij in zip(self.r_values, self._sector_scalars(c_i)):
            base = self._mod(base + self._mod(r_j * c_ij))
        sigma_i = self._mod(base * y_i)
        return y_i, Y_i, sigma_i

    def verify_upload_authenticator(
        self,
        c_i: Sequence[bytes],
        tg_i: int,
        Y_i: int,
        sigma_i: int,
    ) -> bool:
        """上传认证器验证公式：e(sigma_i,g)==e(H2(s||tg_i)*prod_j r_j^{c_i,j},Y_i)。"""
        base = self.H2(self.s_param + int_to_bytes(tg_i, 32))
        for r_j, c_ij in zip(self.r_values, self._sector_scalars(c_i)):
            base = self._mod(base + (r_j * c_ij))
        return self.pairing_equal(sigma_i, self.g, base, Y_i)

    def aggregate_authenticator(
        self,
        indices: Sequence[int],
        coeffs: Sequence[int],
        sigma_store: Dict[int, int],
    ) -> int:
        """ProofGen 聚合公式：sigma_c=prod_i sigma_{x_i}^{v_i} 的指数表示。"""
        sigma_c = 0
        for index, coeff in zip(indices, coeffs):
            weighted = self._mod(sigma_store[index] * self._mod(coeff))
            sigma_c = (sigma_c + weighted) % self.q
        return sigma_c
