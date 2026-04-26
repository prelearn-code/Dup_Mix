# Dup_Mix 论文复现实现说明

本文档说明本项目如何复现论文《Blockchain-Enabled Efficient Deduplication and Mixed Auditing for Dynamic Cloud Data》，包括方案组件、参数来源、核心函数、协议流程、实验指标映射和本地链账户信息。

## 1. 复现口径

项目采用链下协议复现与链上 gas 测量两部分：

- 链下协议严格路径：使用论文 PBC Type-A 群阶的指数表示群元素，并调用本地 C/PBC `pairing_apply` 执行身份验证、上传认证器验证和审计证明验证。实现位置为 `src/crypto.py`、`src/protocol.py`、`src/pbc_pairing.py` 与 `src/pbc_pairing_wrapper.c`。
- 主流程链上路径：`scripts/flows/* --real-chain` 会连接 Ganache、部署 `contracts/AuditSystem.sol`，并把上传、挑战、审计结算、转让请求和转让结算作为真实交易提交。
- 真实文件本地数据库路径：`scripts/flows/real_file_full_flow.py` 直接读取 `data/client_files/` 下的真实文件，并将 Client 状态保存到 `data/client_db/`、CSP 状态保存到 `data/csp_db/`。
- 链上 gas 路径：合约使用 BN254 pairing precompile 测量同结构链上配对验证 gas。实现位置为 `contracts/AuditSystem.sol::verifyBn254ProofAndSettle()` 和 `scripts/paper_tests/test_H_audit_gas.py`。
- 私有 sector 加密：按论文公式 `c_i,j = H3(k_i,j) xor m_i,j` 实现。ECC shared secret 后的 sector key payload 封装由 `src/crypto.py::k_encrypt()` 和 `k_decrypt()` 完成。
- 审计验证边界：主协议的 PBC Type-A VerifyProof 在链下 Python/C-PBC 中完成；合约 `submitProofResult()` 记录链下验证布尔值并结算，不在合约内重算论文 PBC Type-A 公式。BN254 pairing 合约函数用于 H gas 实验。

链上 BN254 gas fixture 由 `scripts/paper_tests/test_H_audit_gas.py::_bn254_pairing_fixture()` 生成。合约内 `Pairing.negate()` 使用 BN254 G1 field modulus `21888242871839275222246405745257275088696311157297823662689037894645226208583` 对点取负；proof fixture 的标量在 BN254 curve order 内生成。

## 2. 固定参数与生成位置

| 论文参数/实验参数 | 取值 | 生成或配置位置 |
| --- | ---: | --- |
| 块大小 | `4096` bytes | `src/crypto.py::setup()` 返回 `GlobalParams.block_size` |
| 每块 sector 数 | `128` | `configs/paper_repro.yaml` 与 `scripts/paper_tests/benchmarks.py::build_runtime()` |
| sector 大小 | `32` bytes | `src/utils.py::split_file_into_blocks_and_sectors()`，由 `4096 / 128` 得到 |
| 重复率 | `0.75` | `configs/paper_repro.yaml`，由 `benchmarks.py::make_file_bytes()` 构造重复块 |
| 私有数据比例 | 常用 `0.5` | `configs/paper_repro.yaml`，由 `benchmarks.py::public_indices()` 转换为 public block index |
| PBC Type-A 阶 | `730750818665421...` | `src/crypto.py::PBC_TYPE_A_ORDER` |
| 随机参数 `R={r_j}` | `128` 个 Type-A 阶内随机数 | `src/crypto.py::setup()` |
| 文件密钥 `fk` | `H1(F)` | `src/crypto.py::f_keygen()` |
| sector 密钥 `k_i,j` | `H1(m_i,j)` | `src/crypto.py::s_keygen()` |
| 文件 tag `t` | `g^fk` 的指数表示 | `src/crypto.py::taggen()` |
| 块 tag `tg_i` | `H1(c_i)` | `src/crypto.py::taggen()` |
| MHT 叶子 `h_i` | `tg_i` | `src/mht.py::_leaf_hash()` 直接返回 block tag |
| MHT 内部节点 `h` | `H(left.h || right.h)` | `src/mht.py::_parent_hash()` |
| MHT 节点三元组 | `(h,lN,p)` | `src/mht.py::_leaf_node()` / `_parent_node()` |
| 身份随机数 `mu` | Type-A 阶内随机数 | `src/crypto.py::generate_user_identity()` |
| 审计挑战 `z/theta1/theta2` | 来自配置或请求 | `src/protocol.py::audit_req()` 和 `benchmarks.py::_challenge()` |
| `f1/f2` | SHA-256 派生 PRP/PRF | `src/crypto.py::f1()` / `src/crypto.py::f2()` |
| Ganache chain id | `1337` | `src/crypto.py::setup()`、`scripts/setup_paper_env.sh`、gas 脚本 |

`configs/paper_repro.yaml` 包含两套实验规模：

- `smoke`：快速流程验证，A-G 小规模运行。
- `full`：论文规模参数，例如 A 的 `1000~10000` blocks，B/C 的 `z=300,460`，D 的 `5000` blocks，E 的 `1000` updates，G 的 `2000 x 4KiB`。

full 模式的 `repeats` 使用 `configs/paper_repro.yaml` 中的配置值。

## 3. 论文算法到代码实现

### Setup

论文内容：生成 `G1/G2/p/e/g/R/H1/H2/H3/H4/f1/f2`。

代码实现：

- `src/crypto.py::setup()`：加载 `libpbc/libgmp`，设置 Type-A 阶、块大小、sector 数、`R`。
- `src/crypto.py::CryptoEngine.__init__()`：初始化严格 `paper_pbc` 路径。
- `src/crypto.py::H1/H2/H3/H4/f1/f2()`：实现论文哈希、密钥流和挑战索引/系数生成。

### KeyGen / Encrypt / TagGen

论文内容：`fk=H1(F)`，`k_i,j=H1(m_i,j)`，私有数据 `c_i,j=H3(k_i,j) xor m_i,j`，文件 tag `t=g^fk`，块 tag `tg_i=H1(c_i)`。

代码实现：

- `src/utils.py::split_file_into_blocks_and_sectors()`：按 `4KiB / 128 sectors` 切分并 padding。
- `src/crypto.py::keygen()`：生成 `fk` 和全部 sector keys。
- `src/crypto.py::s_encrypt()` / `s_decrypt()`：执行 `H3(k) xor data`。
- `src/crypto.py::encrypt_blocks()`：根据 public/private block index 处理混合明文/密文。
- `src/crypto.py::taggen()`：生成文件 tag 和块 tag。

### ECC Key Encapsulation

论文内容：使用 ECC 加密每块 sector key 集合，用户只保留 ECC 私钥。

代码实现：

- `src/crypto.py::k_encrypt()`：用 `coincurve` ECDH 生成 shared secret，再通过 `H3` 密钥流封装 key list。
- `src/crypto.py::k_decrypt()`：用用户 ECC 私钥解封装 key list。
- 数据 sector 加密由 `src/crypto.py::s_encrypt()` / `s_decrypt()` 的 `H3(k) xor data` 完成。

### User Identity Verification

论文公式：`UID=(H4(uid) * t)^mu`，`W=g^mu`，CSP 验证 `e(UID,g) == e(H4(uid) * t,W)`。

代码实现：

- `src/crypto.py::generate_user_identity()`：生成 `mu/UID/W`。
- `src/crypto.py::verify_user_identity()`：执行配对等式验证。
- 调用位置：
  - 上传前：`src/protocol.py::upload_and_dedup_protocol()`
  - 检索前：`src/protocol.py::retrieve_protocol()`
  - 所有权转移后新用户访问：`src/protocol.py::ownership_transfer_protocol()`

### Deduplication

论文内容：先文件级去重，再块级去重；去重在用户/CSP 交互阶段完成。

代码实现：

- `src/storage.py::file_level_dedup_check()`：用文件 tag `t` 检查文件级重复。
- `src/storage.py::block_level_dedup_check()`：用块 tag 集合检查块级重复。
- `src/protocol.py::upload_and_dedup_protocol()`：完整上传去重流程。
- `src/storage.py::store_upload_metadata()`：写入文件索引、文件元数据和所有权记录。
- `src/storage.py::store_key_cipher()`：按 owner 保存 key ciphertext。

### Client / CSP Local Databases

论文内容：Client 持有用户侧身份与访问材料，CSP 持有云端数据、索引、认证器和 key ciphertext。

代码实现：

- `src/local_client_store.py`：结构化保存 Client 侧用户资料、上传记录和取回文件；测试私钥仍来自 `.env`，不会写入 Client DB。
- `src/local_csp_store.py`：结构化保存并加载 `CSPState`，包括文件元数据、块数据、去重索引、HVT 认证器、key payload、ownership 和 audit history。
- `scripts/flows/real_file_full_flow.py`：读取 `data/client_files/` 下的真实文件，执行上传、去重、HVT、上链、审计、取回和权限转移，并落盘 Client/CSP 数据库。

目录结构：

```text
data/client_files/   # 待上传真实文件
data/client_db/      # users/uploads/retrieved
data/csp_db/         # indexes/files/blocks/authenticators/key_ciphers/audit_history
```

CSP DB 索引：

| 文件 | 内容 |
| --- | --- |
| `indexes/file_index.json` | `t -> file_id`，文件级去重 |
| `indexes/block_index.json` | `tg_i -> block_id`，块级去重 |
| `indexes/ownership.json` | `file_id -> owner_address` |
| `files/<file_id>.json` | `FileState`、MHT root、block_ids、block_tags |
| `blocks/<block_id>/sectors.bin` | 实际 public sectors 或 private ciphertext sectors |
| `blocks/<block_id>/meta.json` | tag、owners、sector_values、sector_keys、is_public |
| `authenticators/<block_id>.json` | `sigma/y/Y` |
| `key_ciphers/<block_id>/<owner>.bin` | owner 对应的 ECC key payload |

### AuthGen / Upload Authenticator Verification

论文公式：

- `y_i=(sum_j k_i,j) xor gamma`
- `Y_i=g^y_i`
- `sigma_i=(H2(s||tg_i) * prod_j r_j^{c_i,j})^{y_i}`
- 验证：`e(sigma_i,g) == e(H2(s||tg_i) * prod_j r_j^{c_i,j}, Y_i)`

代码实现：

- `src/crypto.py::authgen()`：生成 `y_i/Y_i/sigma_i`。
- `src/crypto.py::verify_upload_authenticator()`：上传阶段认证器验证。
- `src/storage.py::store_authenticator()`：保存 `sigma/y/Y`。
- `src/protocol.py::upload_and_dedup_protocol()`：对非重复块生成并验证认证器。

### MHT Dynamic Data

论文内容：使用改进 MHT 支持动态插入、修改、删除。

代码实现：

- `src/mht.py::build_improved_mht()`：构造包含 `h/lN/p/tag` 的叶子节点和包含 `h/lN/p/left/right` 的内部节点；树对象保留 `node/root/tags/levels`。
- `src/mht.py::_leaf_hash()`：叶子哈希采用论文图 2 语义 `h_i=tg_i`，不是额外执行 `sha256("leaf|tag")`。
- `src/mht.py::insert_block_mht()`：在指定位置插入新叶子，局部生成新父节点并重算受影响路径。
- `src/mht.py::modify_block_mht()`：替换目标叶子 tag，仅重算从该叶子到 root 的路径。
- `src/mht.py::delete_block_mht()`：删除目标叶子后提升剩余 sibling，并重算到 root 的路径；这对应论文图 2 中删除 `m_1` 后 `h_2` 被提升的结构。
- 协议入口：
  - `src/protocol.py::insert_protocol()`
  - `src/protocol.py::modify_protocol()`
  - `src/protocol.py::delete_protocol()`
- 链交互：`src/chain.py::record_update()` 与 `contracts/AuditSystem.sol::recordUpdate()`。
- 回归测试：`tests/test_mht_utils.py::test_mht_delete_promotes_sibling_like_paper_figure()` 覆盖 sibling 提升行为。

### AuditReq / ProofGen / VerifyProof

论文内容：合约生成挑战 `Chal=(z,theta1,theta2)`，CSP 计算 `P_j=sum_i v_i*c_xi,j`，验证方计算 `sigma_c=prod_i sigma_xi^v_i` 并验证公式 `(8)`。

代码实现：

- `src/protocol.py::audit_req()`：生成随机挑战并可写入链状态。
- `scripts/paper_tests/benchmarks.py::_challenge()`：实验中生成确定性挑战，便于 benchmark 重复。
- `src/protocol.py::proof_gen()`：生成 `indices/coeffs/P/sigma_c/pairing_rhs`。
- `src/crypto.py::pairing_exponent()`：仅用于 proof payload 中记录指数形式的 pairing 右侧摘要，真实等式验证走 `pairing_equal()` / `pairing_product_equal()`。
- `src/protocol.py::verify_proof_protocol()`：重算挑战、`P`、`sigma_c`、`pairing_rhs` 与 pairing 等式，得到本地 PBC Type-A 验证结果。
- `src/chain.py::submit_proof_result()`：调用合约 `submitProofResult()`，链上记录本地严格验证后的布尔结果并结算；该函数不在合约内重算 pairing 公式。

链上 gas 路径：

- `contracts/AuditSystem.sol::Pairing`：BN254 precompile 封装。
- `contracts/AuditSystem.sol::benchmarkVerifyProofAndSettle()`：benchmark-only 的 proof blob checksum/keccak 完整性检查，不是论文 pairing 公式。
- `contracts/AuditSystem.sol::verifyBn254ProofAndSettle()`：执行 `e(-sigmaC,P2) * e(baseAgg,yAgg) == 1` 的同结构 BN254 验证并结算，对应 `e(sigmaC,P2) == e(baseAgg,yAgg)`。
- `scripts/paper_tests/test_H_audit_gas.py::_bn254_pairing_fixture()`：生成 BN254 proof fixture。
- `scripts/paper_tests/test_H_audit_gas.py::main()`：测量 Challenge / Prove / Verify 三阶段 gas。

BN254 G1 点取负使用 `contracts/AuditSystem.sol::Pairing.FIELD_MODULUS`，标量生成使用 BN254 curve order。

### Upload Record / File Stub

论文内容：区块链维护 storage metadata、audit logs、ownership transaction records，并记录费用和保证金相关状态。

代码实现：

- `contracts/AuditSystem.sol::UploadRecord`：链上文件存根，字段为 `owner/tValue/root/fee/deposit/exists`。
- `contracts/AuditSystem.sol::uploads`：`mapping(string => UploadRecord)`，按 `fileId` 保存链上上传记录。
- `contracts/AuditSystem.sol::recordUpload()`：写入文件 tag `tValue`、MHT root `root`、费用和押金，并发出 `StorageUploaded`。
- `contracts/AuditSystem.sol::recordUpdate()`：动态插入、修改、删除后只更新 `uploads[fileId].root`。

对应关系：

| 合约字段 | 论文语义 | 说明 |
| --- | --- | --- |
| `owner` | 数据拥有者 | 工程中使用地址表示 owner |
| `tValue` | 文件 tag `t` | 对应 `src/crypto.py::taggen()` 输出 |
| `root` | MHT root `w_r` / `w_r*` | 上传和动态更新时写链 |
| `fee` | 用户费用 | 工程化费用字段 |
| `deposit` | 保证金机制 | 简化字段；论文更强调 CSP margin |
| `exists` | 存在标记 | 工程索引辅助字段 |

当前合约不保存完整 `T={tg_i}`、`uid`、`SID`、key ciphertext 或 HVT 认证器集合；这些由 CSP 本地状态保存，链上只保存文件级存根和结算状态。

### Retrieval

论文内容：CSP 验证用户身份后返回数据和 key ciphertext；用户解封装 key 并解密私有 sector。

代码实现：

- `src/protocol.py::retrieve_protocol()`：校验 owner、验证 `UID/W`、解封装 key、对私有 block 执行 `s_decrypt()`，最后按原文件大小截断 padding。

### Ownership Transfer

论文内容：购买方发起转移，原 owner 证明身份，CSP 更新 owner，买方验证可解密后结算。

代码实现：

- `src/protocol.py::ownership_transfer_protocol()`：本地协议流程，包含旧 owner 检索、key 重新封装、新 owner 身份生成、CSP ownership 更新、买方检索验证、链上结算。
- `src/chain.py::request_transfer()` / `settle_transfer()`：执行内存链状态或 web3 链状态变更。
- `contracts/AuditSystem.sol::requestTransfer()`、`benchmarkVerifyTransferOwner()`、`benchmarkCspUpdateTransfer()`、`benchmarkFinalizeTransfer()`：I 指标 gas 阶段。
- `scripts/paper_tests/test_I_transfer_gas.py::main()`：测量所有权转移四阶段 gas。

## 4. 实验指标与实现对应

| 指标 | 论文实验含义 | 参数来源 | 运行函数 | 输出文件 |
| --- | --- | --- | --- | --- |
| A | 上传 Tag/Auth 生成开销 | `configs/paper_repro.yaml:a.blocks/repeats/dup_ratio/private_ratio` | `benchmarks.py::bench_a_upload()` | `results/paper_tests/A_upload.csv` |
| B | CSP 证明生成开销 | `b.challenge_blocks/n_blocks`，full 为 `300/460` | `benchmarks.py::bench_b_prove()` -> `protocol.py::proof_gen()` | `B_prove.csv` |
| C | 证明验证开销 | `c.challenge_blocks/n_blocks`，full 为 `300/460` | `benchmarks.py::bench_c_verify()` -> `protocol.py::verify_proof_protocol()` | `C_verify.csv` |
| D | 私有 block 加密/解密开销 | `d.private_ratios/n_blocks` | `benchmarks.py::bench_d_encrypt_decrypt()` -> `crypto.py::encrypt_blocks()/s_decrypt()` | `D_encrypt_decrypt.csv` |
| E | 动态更新开销 | `e.updates/n_blocks`，full 为 `1000` updates | `benchmarks.py::bench_e_update()` -> `protocol.py::insert_protocol()` | `E_update.csv` |
| F | 通信开销估算 | `f.blocks/challenge_blocks` | `benchmarks.py::bench_f_communication()` | `F_communication.csv` |
| G | 文件级去重综合实验 | full 为 `2000 blocks, w=0.5, z=460` | `benchmarks.py::bench_g_file_dedup()` | `G_file_level_dedup.csv` |
| H | 审计链上 gas | Ganache + BN254 precompile | `scripts/paper_tests/test_H_audit_gas.py` | `H_audit_gas.csv` |
| I | 所有权转移 gas | Ganache + ownership transfer contract stages | `scripts/paper_tests/test_I_transfer_gas.py` | `I_transfer_gas.csv` |

## 5. 本地链账户信息

本地链使用命令：

```bash
ganache \
  --wallet.mnemonic "copper wave move caught main cruise derive inherit team sister make escape" \
  --chain.chainId 1337 \
  --chain.hardfork shanghai \
  --server.host 127.0.0.1 \
  --server.port 7545 \
  --wallet.totalAccounts 10
```

RPC：

```text
http://127.0.0.1:7545
```

本地测试账户，仅用于 Ganache：

| index | address | private key |
| ---: | --- | --- |
| 0 | `0xAB99A8D8d8deE736a6B8f40D8fFA98694B745138` | `0x267f8358dbcb414f3567eb48cbd173f4b035cde77baf58b8f36823acc8db8ed1` |
| 1 | `0x24291Ea0B8aB706e1a576beBC869A2b63072f265` | `0x308539265331010d37c2e16d3b27fcc6a71dff6ffcb26175d4fc2af0e7b36dd8` |
| 2 | `0x2ad9a1698a5309dB005cea681150362Ab99Dc1B3` | `0x19d737f6b2ac3b146ff985de0dded5b5d11b694f26bb0dd92b0f75c88ad04897` |
| 3 | `0x7021Fb52487AC1c1733cC47A846dB474B25D01Ab` | `0x61cabe658a8c206a440bfb65641c9a8a76fcd3915c9e9064fc4763b9e2c4ea83` |
| 4 | `0x7639bC3411158e78577aD6f032d92A9B29B1638c` | `0xd65bc828d92742e4d77735c6301cc5e96546701b4cb915b1d29fcd755c198d0b` |
| 5 | `0x0a40C98d62f93252b4070F06775d346EcAC08C5d` | `0x2d793a32e3806d3dad21de9576b33417e573f56d9f0895be5df2188dc3db792e` |
| 6 | `0x5D28982fBdbF84fe864b5c16D7bd55E1B0d427bD` | `0x1c3f2f82ed406ed19a27fd6564bbdd6a86cc3786113f611aa7485afc6114eea4` |
| 7 | `0x2cE6750cA28Cc60E7D94fD610ec8EC45114C3766` | `0xc15f8746c0cc2b92461a34942c7e382c471f357dae33de080684be2c4015f4f0` |
| 8 | `0xEE5aD791E08745453A4eb3738fB1c6C20C469e55` | `0xa8ba885a21d067ad6412f14e9d097a4cd3d351df79c8f7f5456b3252de596f2c` |
| 9 | `0xB44C0D0Ff834e3763246b2187b1e9C000DBC6C33` | `0x242152806cadeaca8952119026e145e5bcce312cad33af19c00fa6970ab3fe58` |

benchmark 默认角色：

- H gas：`accounts[0]` 为 owner/deployer，`accounts[1]` 为 requester，`accounts[2]` 为 CSP。
- I gas：`accounts[0]` 为 from owner，`accounts[1]` 为 to owner，`accounts[2]` 为 CSP。
- `scripts/paper_tests/benchmarks.py::build_runtime()` 中协议 benchmark 使用 `accounts[1]` 风格地址作为 `user1`，`accounts[2]` 作为 `user2`，`accounts[3]` 作为 CSP。

## 6. 全程测试结果

最近一次回归时间：2026-04-26。

基础回归命令：

```bash
./.venv/bin/python -m pytest -q
```

结果：

- 单元测试：`20 passed`。
- 覆盖内容：协议端到端、审计证明篡改失败、合约 mock 状态、MHT sibling 提升、MHT/AVT 与工具函数。

真实链全流程命令：

```bash
ganache --wallet.mnemonic "copper wave move caught main cruise derive inherit team sister make escape" \
  --chain.chainId 1337 --chain.hardfork shanghai \
  --server.host 127.0.0.1 --server.port 7545 --wallet.totalAccounts 10

GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/01_upload_dedup_store_flow.py --real-chain
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/02_audit_request_flow.py --real-chain
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/03_retrieve_decrypt_flow.py --real-chain
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/04_ownership_transfer_flow.py --real-chain
```

真实链全流程结果：

- 上传流程：`chain_backend=web3`，`recordUpload` 交易 `status=1`，示例 gas `277240`。
- 审计流程：`chain_backend=web3`，`createAuditRequest` 和 `submitProofResult` 交易 `status=1`，`verified=true`，链上 `is_valid=true`。
- 取回流程：`chain_backend=web3`，`retrieve_match=true`。
- 转让流程：`chain_backend=web3`，`requestTransfer/settleTransfer` 上链，`transfer_success=true`，`buyer_retrieve_match=true`。

论文指标回归命令：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics all
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
./.venv/bin/python scripts/paper_tests/build_report.py
```

论文指标状态：

- full A-G：输出到 `results/paper_tests/`。
- H gas：`chain_pairing_backend=BN254_PRECOMPILE`。
- I gas：所有权转移阶段 gas 输出到 `I_transfer_gas.csv`。

full 输出摘要：

| 文件 | 关键结果 |
| --- | --- |
| `A_upload.csv` | `1000/3000/5000/8000/10000` blocks 的 tag/auth 开销 |
| `B_prove.csv` | `z=300/460` proof 生成开销：`13.3049 ms` / `19.6913 ms` |
| `C_verify.csv` | `z=300/460` 本地 PBC 验证开销：`12.6648 ms` / `19.3521 ms` |
| `D_encrypt_decrypt.csv` | `w=0.2/0.5/0.8/1.0` 加解密开销 |
| `E_update.csv` | `1000` 次插入更新，总计 `2.803335 s` |
| `F_communication.csv` | `1000/3000/5000` blocks upload 与 `z=300/460` audit 通信估算 |
| `G_file_level_dedup.csv` | `2000` blocks 文件级去重，`duplicate_detected=True`，`verify_ok=True` |
| `H_audit_gas.csv` | Challenge `98613`，Prove `509698`，Verify `196763` gas |
| `I_transfer_gas.csv` | Request `150844`，OwnerVerify `70907`，CspUpdate `70351`，Finalize `54700` gas |
| `paper_vs_measured_summary.csv` | 汇总 A-I 指标实测结果与报告字段 |

## 7. 运行方式

快速 mock 验证：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode smoke --metrics all
./.venv/bin/python -m pytest -q
```

论文规模 A-G：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics a,b,c,d,e,f,g
```

链上 H/I：

```bash
ganache --wallet.mnemonic "copper wave move caught main cruise derive inherit team sister make escape" \
  --chain.chainId 1337 --chain.hardfork shanghai \
  --server.host 127.0.0.1 --server.port 7545 --wallet.totalAccounts 10

GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
```

真实链全流程：

```bash
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/01_upload_dedup_store_flow.py --real-chain
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/02_audit_request_flow.py --real-chain
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/03_retrieve_decrypt_flow.py --real-chain
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/04_ownership_transfer_flow.py --real-chain
```

真实文件完整流程：

```bash
# 先把真实文件放入 data/client_files/
./.venv/bin/python scripts/flows/real_file_full_flow.py
```
