# Dup_Mix

本项目复现论文《Blockchain-Enabled Efficient Deduplication and Mixed Auditing for Dynamic Cloud Data》的核心协议流程与实验指标。链下协议使用 PBC Type-A 群阶上的指数表示群元素，并通过本地 C/PBC `pairing_apply` 执行身份验证、认证器验证和审计证明验证；链上 gas 实验使用 Ganache 与 Solidity 合约执行对应阶段的状态记录和 BN254 配对验证。

## 目录结构

| 路径 | 作用 |
| --- | --- |
| `src/crypto.py` | `H1/H2/H3/H4`、`f1/f2`、sector key、`H3(k) xor data`、ECC key payload 封装、tag、authenticator、pairing 验证入口 |
| `src/pbc_pairing.py` / `src/pbc_pairing_wrapper.c` | Python ctypes 封装与 C/PBC `pairing_apply` wrapper |
| `src/protocol.py` | 上传去重、审计、取回解密、动态更新、权限转让的协议编排 |
| `src/storage.py` | CSP 本地 file/block 去重索引、认证器、key payload、ownership 元数据 |
| `src/mht.py` | 本地 MHT/AVT 树构造、插入、修改、删除 |
| `src/chain.py` | 内存链状态与 Ganache/web3 合约交互封装 |
| `src/local_csp_store.py` | CSP 结构化本地数据库保存/加载 |
| `src/local_client_store.py` | Client 本地用户与上传记录保存/加载 |
| `contracts/AuditSystem.sol` | 上传、审计、更新、转让记录，以及 BN254 pairing gas 路径 |
| `scripts/flows/` | 面向单流程测试的集成脚本 |
| `scripts/paper_tests/` | A-I 实验指标脚本与报告生成 |
| `PROJECT_REPRODUCTION_MAPPING.md` | 参数、函数、流程、实验指标与本地链账户映射说明 |

## 安装与环境检查

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

检查本地依赖、PBC/GMP、Ganache、solc：

```bash
./.venv/bin/python scripts/check_paper_env.py --check-pbc-property
./.venv/bin/python scripts/check_pairing_backend.py
```

从 GitHub 克隆后，仓库不会包含本地数据库、实验输出和批量真实文件；这些内容都可以由脚本重新生成。项目保留论文 PDF、源码、合约、测试、实验脚本和复现配置。

```bash
./.venv/bin/python scripts/generate_experiment_files.py
```

该命令会在 `data/client_files/` 下生成约 100 个确定性真实上传文件，并写入 `data/client_files/manifest.json`。文件覆盖论文实验中的核心变量：块数、文件级重复、块级重复、75% 重复率审计文件、动态更新文件。生成的数据不进入 Git，后续可以随时删除后重建。

如果要运行真实链流程或 gas 脚本，先启动 Ganache。推荐从 `.env` 读取固定 mnemonic 和 chain id，保证每次启动的账户都和项目配置一致：

```bash
set -a
source .env
set +a

ganache \
  --wallet.mnemonic "$GANACHE_MNEMONIC" \
  --chain.chainId "$GANACHE_CHAIN_ID" \
  --chain.hardfork shanghai \
  --server.host 127.0.0.1 \
  --server.port 7545 \
  --wallet.totalAccounts 10
```

## 单流程集成脚本

`01/03/04` 默认使用内存链，便于快速测试完整协议调用；加 `--real-chain` 后会连接 `GANACHE_RPC_URL` 或默认 `http://127.0.0.1:7545` 并部署合约。`02_audit_request_flow.py` 是持久化数据库审计入口，默认连接真实 Ganache/web3；如需内存链测试，显式加 `--mock-chain`。

### 1. 上传、去重、CSP 存储、MHT/AVT 更新、链上记录

```bash
./.venv/bin/python scripts/flows/01_upload_dedup_store_flow.py
```

该流程调用：

- `src.crypto.setup()` / `CryptoEngine(...)` 初始化全局参数。
- `src.protocol.upload_and_dedup_protocol()` 完成文件切分、keygen、私有 sector 加密、tag 生成、UID/W 生成、CSP 身份验证、文件级/块级去重、认证器生成与验证、CSP 本地存储。
- `src.mht.build_improved_mht()` 在协议内部生成本地 MHT/AVT root。
- `src.chain.record_upload()` 在协议内部写入链上上传记录。

### 2. 用户审计请求、CSP 证明、验证与结算

```bash
./.venv/bin/python scripts/flows/02_audit_request_flow.py
```

该流程调用：

- 从 `data/csp_db/` 加载所有已上传文件，默认把所有文件作为候选范围，随机选择一个文件并随机选择挑战块数 `z`。
- `src.protocol.audit_req()` 生成 `z/theta1/theta2` 并创建链上 challenge 记录。
- `src.protocol.proof_gen()` 由 CSP 生成 `indices/coeffs/P/sigma_c/pairing_rhs`。
- `src.protocol.verify_proof_protocol()` 在链下 Python/C-PBC 路径重算挑战并验证 pairing 等式。
- `src.chain.submit_proof_result()` 调用合约 `submitProofResult()`，只把链下验证得到的 `isValid` 写入链上并完成结算。

常用选项：

```bash
./.venv/bin/python scripts/flows/02_audit_request_flow.py --seed 7 --max-challenge-blocks 5
./.venv/bin/python scripts/flows/02_audit_request_flow.py --all --max-challenge-blocks 2
./.venv/bin/python scripts/flows/02_audit_request_flow.py --file-id file-xxxx
./.venv/bin/python scripts/flows/02_audit_request_flow.py --mock-chain
```

### 3. 用户取回数据并解密

```bash
./.venv/bin/python scripts/flows/03_retrieve_decrypt_flow.py
```

该流程调用：

- `src.protocol.retrieve_protocol()` 校验 owner、验证 UID/W、读取 CSP 保存的 key payload。
- `src.crypto.k_decrypt()` 解封装 private block 的 sector keys。
- `src.crypto.s_decrypt()` 对私有 sector 执行 `H3(k) xor ciphertext`。

### 4. 权限转让

```bash
./.venv/bin/python scripts/flows/04_ownership_transfer_flow.py
```

该流程调用：

- `src.protocol.ownership_transfer_protocol()` 发起链上转让请求、验证旧 owner 可取回数据、为新 owner 重新封装 private sector keys、更新 CSP ownership、让新 owner 检索验证。
- `src.chain.request_transfer()` 和 `src.chain.settle_transfer()` 记录转让请求与结算结果。

## 真实链全流程实验

先启动 Ganache。使用 `.env` 中的 `GANACHE_MNEMONIC` 和 `GANACHE_CHAIN_ID`，保证每次启动得到固定账户，并与 `scripts/flows/flow_common.py` 中的 owner、buyer、CSP 测试账户匹配：

```bash
set -a
source .env
set +a

ganache \
  --wallet.mnemonic "$GANACHE_MNEMONIC" \
  --chain.chainId "$GANACHE_CHAIN_ID" \
  --chain.hardfork shanghai \
  --server.host 127.0.0.1 \
  --server.port 7545 \
  --wallet.totalAccounts 10
```

另开一个终端执行完整真实链流程。每个脚本都会连接 Ganache、部署 `AuditSystem` 合约，并提交真实交易。注意：`02_audit_request_flow.py` 默认读取 `data/csp_db/` 中已经上传的文件，因此应先运行上传或真实文件全流程。

```bash
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/01_upload_dedup_store_flow.py --real-chain
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/02_audit_request_flow.py
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/03_retrieve_decrypt_flow.py --real-chain
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/flows/04_ownership_transfer_flow.py --real-chain
```

成功时输出中应看到：

- `chain_backend: "web3"`，表示走真实 Ganache/web3 路径。
- 交易字段包含 `tx_hash`、`gas_used`、`status: 1` 或 `status_code: 1`。
- 审计流程包含 `verified: true` 和链上 `is_valid: true`。
- 取回流程包含 `retrieve_match: true`。
- 转让流程包含 `transfer_success: true` 和 `buyer_retrieve_match: true`。

如果只想运行真实链 gas 指标，使用 H/I 脚本即可；如果要验证完整业务流程，优先运行真实文件完整流程或批量真实文件流程。

## 真实文件完整流程

该入口直接使用目录中的真实文件，并把 Client/CSP 状态写入本地结构化数据库。

目录约定：

```text
data/client_files/   # 放入待上传真实文件
data/client_db/      # Client 本地数据库，保存用户资料、上传记录、取回文件
data/csp_db/         # CSP 本地数据库，保存文件索引、块数据、HVT、key payload、审计历史
```

运行前先生成论文实验数据文件：

```bash
./.venv/bin/python scripts/generate_experiment_files.py
```

单文件全流程会优先读取 `data/client_files/manifest.json`，按 manifest 顺序处理文件。默认只处理第一个文件：

```bash
./.venv/bin/python scripts/flows/real_file_full_flow.py
```

指定连续处理前 N 个文件：

```bash
./.venv/bin/python scripts/flows/real_file_full_flow.py --count 3
```

该脚本固定执行完整业务链路：

- Client 读取真实文件并生成上传请求、`fk`、sector keys、文件 tag `t`、块 tag `tg_i`。
- CSP 执行文件级去重和块级去重。
- CSP 对新块生成 HVT 认证器 `sigma_i/y_i/Y_i`。
- CSP 将真实块/密文块、索引、认证器、key payload 和 ownership 写入 `data/csp_db/`。
- 合约记录 upload，随后执行审计请求、证明生成、链下 PBC 验证和链上结算。
- Client 取回文件并写入 `data/client_db/retrieved/`。
- 执行 owner 到 buyer 的权限转移，CSP 重封装 key，buyer 再次取回验证。

该脚本要求 Ganache 已按 `.env` 配置启动，因为它会连接真实链并部署 `AuditSystem`。测试私钥仍只来自 `.env`，不会写入 `data/client_db/`。

如果要观察批量上传、去重、HVT、审计、取回和权限转让的详细交互日志，使用批量真实文件流程：

```bash
./.venv/bin/python scripts/flows/batch_real_file_full_flow.py --fresh --limit 5
```

默认读取 `data/client_files/*.bin`。`--fresh` 会清空并重建 `data/client_db/` 与 `data/csp_db/`，但不会删除 `data/client_files/`。完整批量实验可去掉 `--limit`：

```bash
./.venv/bin/python scripts/flows/batch_real_file_full_flow.py --fresh
```

批量脚本会输出并记录以下阶段：

- `upload:request`：Client 上传请求、文件大小、块数、public/private 块统计。
- `upload:identity`：CSP 验证用户身份公式。
- `dedup:file` / `dedup:block`：文件级和块级去重结果、新块与重复块数量。
- `upload:payload`：Client 上传密文块、tag、key payload 等信息。
- `csp:store`：CSP 本地数据库新增文件、块、认证器、key cipher 数量。
- `hvt`：HVT/MHT leaf 数、节点数、高度和 root。
- `chain:upload`：智能合约上传记录交易、`tx_hash`、`gas_used`。
- `audit:*`：随机挑战、证明生成、链下 PBC 验证和链上结算。
- `retrieve:*`：owner/buyer 取回与哈希匹配。
- `transfer:*`：权限转让、CSP key 重封装和链上结算。

结构化日志写入：

```text
results/real_file_batch_flow/events.jsonl
results/real_file_batch_flow/summary.json
```

这些结果文件不上传 GitHub，可重新运行生成。

## 从零复现推荐顺序

以下流程不依赖已提交的数据库或结果文件，适合 GitHub 克隆后完整复现：

```bash
# 1. 安装依赖
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# 2. 检查严格 PBC/pairing 环境
./.venv/bin/python scripts/check_paper_env.py --check-pbc-property
./.venv/bin/python scripts/check_pairing_backend.py

# 3. 生成论文实验真实文件
./.venv/bin/python scripts/generate_experiment_files.py

# 4. 另一个终端按 .env 启动 Ganache
set -a
source .env
set +a
ganache \
  --wallet.mnemonic "$GANACHE_MNEMONIC" \
  --chain.chainId "$GANACHE_CHAIN_ID" \
  --chain.hardfork shanghai \
  --server.host 127.0.0.1 \
  --server.port 7545 \
  --wallet.totalAccounts 10

# 5. 跑真实文件完整流程，生成本地 Client/CSP 数据库
./.venv/bin/python scripts/flows/real_file_full_flow.py --count 3

# 6. 单独审计请求：默认从 data/csp_db 的所有文件中随机选择
./.venv/bin/python scripts/flows/02_audit_request_flow.py --seed 7 --max-challenge-blocks 5

# 7. 批量交互流程，可观察上传去重、HVT、审计、取回、转让细节
./.venv/bin/python scripts/flows/batch_real_file_full_flow.py --fresh --limit 5

# 8. 跑论文 A-I 指标
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode smoke --metrics all
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
./.venv/bin/python scripts/paper_tests/build_report.py

# 9. 单元/集成测试
./.venv/bin/python -m pytest -q
```

如果机器性能足够，可以把第 8 步的 smoke 替换为论文规模：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics all
```

## 论文实验脚本

快速 smoke：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode smoke --metrics all
```

论文规模 A-G：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics all
```

链上 H/I gas：

```bash
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
GANACHE_RPC_URL=http://127.0.0.1:7545 ./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
```

生成报告：

```bash
./.venv/bin/python scripts/paper_tests/build_report.py
```

输出位于 `results/paper_tests/`。

## 测试

完整 pytest：

```bash
./.venv/bin/python -m pytest -q
```

按模块分层测试：

```bash
./.venv/bin/python -m pytest tests/test_mht_utils.py -q
./.venv/bin/python -m pytest tests/test_protocol.py -q
./.venv/bin/python -m pytest tests/test_contract.py -q
./.venv/bin/python -m pytest tests/test_local_stores.py -q
./.venv/bin/python -m pytest tests/test_storage.py tests/test_utils_unit.py -q
```

推荐回归顺序：

```bash
./.venv/bin/python scripts/check_paper_env.py --check-pbc-property
./.venv/bin/python -m pytest -q
./.venv/bin/python scripts/flows/01_upload_dedup_store_flow.py
./.venv/bin/python scripts/flows/02_audit_request_flow.py
./.venv/bin/python scripts/flows/03_retrieve_decrypt_flow.py
./.venv/bin/python scripts/flows/04_ownership_transfer_flow.py
```

当前核心验证包括：

- 上传、审计、验证、取回端到端流程。
- 审计证明篡改失败。
- 合约 mock 状态更新。
- Client/CSP 本地数据库保存、加载和取回恢复。
- MHT/AVT 与工具函数。

## 当前实现口径

- 数据 sector 加密使用论文形式 `H3(k) xor data`。
- ECC key payload 使用 ECDH shared secret 派生 `H3` 密钥流封装。
- 链下群元素仍以 PBC Type-A 群阶指数表示，等式验证调用本地 C/PBC `pairing_apply` 比较真实 `GT` 元素。
- 主流程审计验证不在合约中重算论文 PBC Type-A 公式；合约 `submitProofResult()` 只记录链下验证结果并结算。
- 链上 pairing gas 使用 BN254 precompile，对应实现为 `contracts/AuditSystem.sol::verifyBn254ProofAndSettle()`，验证公式形态为 `e(-sigmaC,P2) * e(baseAgg,yAgg) == 1`。
- A-G 默认使用内存链统计链下协议开销；H/I 使用 Ganache 真实交易 receipt 统计 gas。
