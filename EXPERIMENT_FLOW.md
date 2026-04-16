# Experiment Flow

本文档给出当前仓库的完整实验流程，说明每一步运行了什么、做了什么、产出了什么结果。

## 1. 实验目标

当前实验分为三部分：

1. 环境与严格双线性配对后端检查
2. 离线 benchmark（A-G）
3. 真实链 gas benchmark（H-I）

最终所有结果都写入 `results/paper_tests/`。

模式说明：

- `smoke`：流程验证模式，默认 `chain_mode=mock`，不用于论文严格数值对照。
- `full`：论文参数模式，默认 `chain_mode=real`，用于论文口径复现。
- 每次 `run_paper_repro.py` 会输出 `run_meta_<mode>.json`，可查看 `paper_scale/comparable` 字段。

## 2. 环境准备

### Step 1: 基础环境初始化

运行命令：

```bash
cp .env.example .env
bash scripts/bootstrap_env.sh
```

这一步做了什么：

- 创建 `./.venv`
- 安装 `requirements.txt`
- 检查基础依赖

输出：

- Python 虚拟环境
- 已安装依赖

### Step 2: 严格复现环境检查

运行命令：

```bash
bash scripts/setup_paper_env.sh
./.venv/bin/python scripts/check_paper_env.py
```

这一步做了什么：

- 检查 Python 版本
- 检查 `web3`、`solcx`、`coincurve`、`gmpy2`、`py_ecc`
- 检查 `libpbc.so`、`libgmp.so`
- 检查 Ganache 命令和 RPC
- 检查本地 `solc`

当前结果：

- `Python 3.10.12`
- `libpbc.so`: OK
- `libgmp.so`: OK
- `ganache rpc 127.0.0.1:7545`: OK
- `solc versions`: `0.8.20`
- `REPRO_MODE`: `FULL_REPRO`

### Step 3: 严格双线性配对后端检查

运行命令：

```bash
DUPMIX_PAIRING_BACKEND=paper_pbc DUPMIX_REQUIRE_STRICT_PBC=1 ./.venv/bin/python scripts/check_pairing_backend.py
DUPMIX_PAIRING_BACKEND=paper_pbc ./.venv/bin/python scripts/check_paper_env.py --check-pbc-property
```

这一步做了什么：

- 强制系统使用严格配对后端
- 检查 `pairing_strict`
- 检查双线性配对性质测试是否通过

当前结果：

- `pairing_backend=paper_pbc`
- `use_pbc=True`
- `pairing_strict=True`
- `pairing property: OK`

## 3. Ganache 启动

### Step 4: 启动真实链

运行命令：

```bash
ganache \
  --server.host 127.0.0.1 \
  --server.port 7545 \
  --chain.chainId 1337 \
  --wallet.totalAccounts 10
```

这一步做了什么：

- 启动本地 RPC
- 提供固定账户、私钥和 gas 环境

作用：

- H 指标和 I 指标依赖真实链交易回执 `gasUsed`

## 4. 离线实验 A-G

### Step 5: 运行 smoke 模式离线实验

运行命令：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode smoke --metrics all
```

这一步做了什么：

- 从 `configs/paper_repro.yaml` 读取 `smoke` 参数
- 自动运行 A-G 指标
- 将结果写入 `results/paper_tests/*.csv` / `*.json`
- 输出 `results/paper_tests/run_meta_smoke.json`

### Step 6: 当前 A-G 结果

#### A 上传阶段

运行内容：

- 统计 `avg_tag_ms`
- 统计 `avg_auth_ms`

结果文件：

- [A_upload.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/A_upload.csv)

当前结果：

```text
n_blocks=100  avg_tag_ms=0.4245   avg_auth_ms=9.5603
n_blocks=300  avg_tag_ms=1.3117   avg_auth_ms=29.0436
```

#### B Prove

结果文件：

- [B_prove.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/B_prove.csv)

当前结果：

```text
challenge_blocks=50   avg_prove_ms=1.8973
challenge_blocks=100  avg_prove_ms=3.6768
```

#### C Verify

结果文件：

- [C_verify.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/C_verify.csv)

当前结果：

```text
challenge_blocks=50   avg_verify_ms=1.7756
challenge_blocks=100  avg_verify_ms=3.8747
```

#### D 加密 / 解密

结果文件：

- [D_encrypt_decrypt.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/D_encrypt_decrypt.csv)

当前结果：

```text
private_ratio=0.2  avg_encrypt_ms=450.3071   avg_decrypt_ms=540.9870
private_ratio=0.5  avg_encrypt_ms=1133.1409  avg_decrypt_ms=1321.5454
private_ratio=0.8  avg_encrypt_ms=1774.3988  avg_decrypt_ms=2098.2459
```

#### E 动态更新

结果文件：

- [E_update.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/E_update.csv)

当前结果：

```text
num_updates=50  total_update_ms=245.5179  avg_update_ms=4.9104
```

#### F 通信开销

结果文件：

- [F_communication.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/F_communication.csv)

当前结果：

```text
upload n_blocks=300     comm_bytes=4387350
audit  challenge=100    comm_bytes=7632
audit  challenge=200    comm_bytes=10953
```

#### G 文件级去重

结果文件：

- [G_file_level_dedup.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/G_file_level_dedup.csv)

当前结果：

```text
file_blocks=500
private_ratio=0.5
challenge_blocks=200
file_tag_ms=1.8338
encrypt_ms=1074.3927
prove_ms=7.3566
verify_ms=7.0522
second_upload_ms=1616.5055
duplicate_detected=True
verify_ok=True
```

## 5. 真实链 gas 实验 H-I

### Step 7: 审计 gas

运行命令：

```bash
./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
```

这一步做了什么：

- 部署 [AuditSystem.sol](/home/zsw/codes/Dup_Mix2/contracts/AuditSystem.sol)
- 上链记录上传信息
- 分阶段统计：
  - `Challenge`
  - `Prove`
  - `Verify`

结果文件：

- [H_audit_gas.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/H_audit_gas.csv)

当前结果：

```text
challenge_gas=98547
prove_gas=47759
verify_gas=73934
```

### Step 8: 所有权转移 gas

运行命令：

```bash
./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
```

这一步做了什么：

- 部署合约
- 分阶段统计：
  - `requestTransfer`
  - `benchmarkVerifyTransferOwner`
  - `benchmarkCspUpdateTransfer`
  - `benchmarkFinalizeTransfer`

结果文件：

- [I_transfer_gas.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/I_transfer_gas.csv)

当前结果：

```text
request_gas=145767
owner_verify_gas=47803
csp_update_gas=47110
finalize_gas=54767
```

## 6. 系统正确性验证

### Step 9: 跑单元测试

运行命令：

```bash
./.venv/bin/pytest -q
```

这一步做了什么：

- 验证协议流程
- 验证合约 mock 生命周期
- 验证存储与工具模块
- 验证 MHT 与基础函数

当前结果：

```text
19 passed, 1 warning
```

## 7. 一次完整实验怎么跑

从头到尾推荐顺序：

```bash
cp .env.example .env
bash scripts/bootstrap_env.sh
bash scripts/setup_paper_env.sh
DUPMIX_PAIRING_BACKEND=paper_pbc DUPMIX_REQUIRE_STRICT_PBC=1 ./.venv/bin/python scripts/check_pairing_backend.py
DUPMIX_PAIRING_BACKEND=paper_pbc ./.venv/bin/python scripts/check_paper_env.py --check-pbc-property
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode smoke --metrics all
./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
./.venv/bin/pytest -q
```

如果要跑论文规模参数：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics a,b,c,d,e,f,g
```

## 8. 最终产物

实验结束后，关键产物包括：

- 环境检查结果
- 严格配对检查结果
- A-I 指标 CSV / JSON
- 单元测试结果

主要目录：

- `results/paper_tests/`
- [README.md](/home/zsw/codes/Dup_Mix2/README.md)
- [TEST_STANDARDS.md](/home/zsw/codes/Dup_Mix2/TEST_STANDARDS.md)
- [REPRO_PLAN.md](/home/zsw/codes/Dup_Mix2/REPRO_PLAN.md)
