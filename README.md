# DupMix2

这个仓库是论文《Blockchain-Enabled Efficient Deduplication and Mixed Auditing for Dynamic Cloud Data》的复现工程，当前已经具备：

- 系统实现
- 严格双线性配对后端
- 论文参数驱动的 benchmark
- 真实链 gas 统计

## 项目结构

- `src/`
  系统核心实现
- `contracts/`
  Solidity 合约
- `scripts/paper_tests/`
  论文实验脚本
- `configs/paper_repro.yaml`
  论文实验参数
- `results/paper_tests/`
  实验结果输出

## 系统由什么组成

- [crypto.py](/home/zsw/codes/Dup_Mix2/src/crypto.py)
  哈希、扇区密钥、块加密、认证器、身份验证、严格双线性配对后端。
- [protocol.py](/home/zsw/codes/Dup_Mix2/src/protocol.py)
  上传去重、审计挑战、证明生成、证明验证、检索、动态更新、所有权转移。
- [storage.py](/home/zsw/codes/Dup_Mix2/src/storage.py)
  文件级/块级去重和状态存储。
- [mht.py](/home/zsw/codes/Dup_Mix2/src/mht.py)
  动态更新所需的 Merkle Hash Tree。
- [chain.py](/home/zsw/codes/Dup_Mix2/src/chain.py)
  mock 链与真实链交互。
- [AuditSystem.sol](/home/zsw/codes/Dup_Mix2/contracts/AuditSystem.sol)
  审计与所有权转移合约。

## 实验数据是怎么产生的

实验数据由脚本自动生成，流程是固定的：

1. 从 [paper_repro.yaml](/home/zsw/codes/Dup_Mix2/configs/paper_repro.yaml) 读取论文参数。
2. `scripts/paper_tests/benchmarks.py` 生成测试文件。
   固定使用 `4 KiB` 块、`128` 个 sector、重复率 `75%`。
3. 调用 [protocol.py](/home/zsw/codes/Dup_Mix2/src/protocol.py) 和 [crypto.py](/home/zsw/codes/Dup_Mix2/src/crypto.py) 执行上传、审计、更新、去重等流程。
4. 统计 A-I 指标。
   A-G 是离线开销，H-I 是真实链 `gasUsed`。
5. 写入 `results/paper_tests/*.csv` 和 `results/paper_tests/*.json`。

## 对应论文指标

- A：上传阶段 `Tag/Auth`
- B：`Prove`
- C：`Verify`
- D：加密 / 解密
- E：动态更新
- F：通信开销
- G：文件级去重
- H：审计 gas
- I：所有权转移 gas

## 环境准备

基础初始化：

```bash
cp .env.example .env
bash scripts/bootstrap_env.sh
```

严格复现环境检查：

```bash
bash scripts/setup_paper_env.sh
./.venv/bin/python scripts/check_paper_env.py
```

严格配对后端检查：

```bash
DUPMIX_PAIRING_BACKEND=paper_pbc DUPMIX_REQUIRE_STRICT_PBC=1 ./.venv/bin/python scripts/check_pairing_backend.py
DUPMIX_PAIRING_BACKEND=paper_pbc ./.venv/bin/python scripts/check_paper_env.py --check-pbc-property
```

当前严格模式下应看到：

- `pairing_strict=True`
- `REPRO_MODE: FULL_REPRO`
- `pairing property: OK`

## Ganache

真实链实验前先启动 Ganache：

```bash
ganache \
  --server.host 127.0.0.1 \
  --server.port 7545 \
  --chain.chainId 1337 \
  --wallet.totalAccounts 10
```

## 运行实验

统一按配置运行：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode smoke --metrics all
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics all
```

模式说明：

- `smoke`
  默认 `chain_mode=mock`，用于快速验证流程是否跑通。
- `full`
  默认 `chain_mode=real`，按论文规模参数执行，目标是论文口径复现。

运行后会额外输出：

- `results/paper_tests/run_meta_smoke.json`
- `results/paper_tests/run_meta_full.json`

其中包含 `chain_mode`、`pairing_strict`、`paper_scale`、`comparable` 等字段。

只运行某几个指标：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics a,b,c
```

`H/I` 为真实链 gas 指标，请单独运行：

```bash
./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
```

单独运行脚本：

```bash
./.venv/bin/python scripts/paper_tests/test_A_upload.py
./.venv/bin/python scripts/paper_tests/test_B_prove.py
./.venv/bin/python scripts/paper_tests/test_C_verify.py
./.venv/bin/python scripts/paper_tests/test_D_encrypt_decrypt.py
./.venv/bin/python scripts/paper_tests/test_E_update.py
./.venv/bin/python scripts/paper_tests/test_F_communication.py
./.venv/bin/python scripts/paper_tests/test_G_file_dedup.py
./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
```

## 怎么测试这个实验

如果你想完整测试一遍，推荐按下面顺序执行。

### 1. 先检查环境

```bash
bash scripts/setup_paper_env.sh
./.venv/bin/python scripts/check_paper_env.py
```

如果要确认严格双线性配对后端已经启用：

```bash
DUPMIX_PAIRING_BACKEND=paper_pbc DUPMIX_REQUIRE_STRICT_PBC=1 ./.venv/bin/python scripts/check_pairing_backend.py
DUPMIX_PAIRING_BACKEND=paper_pbc ./.venv/bin/python scripts/check_paper_env.py --check-pbc-property
```

你应该看到：

- `pairing_strict=True`
- `REPRO_MODE: FULL_REPRO`
- `pairing property: OK`

### 2. 跑离线实验

先跑一版小规模 smoke：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode smoke --metrics all
```

如果 smoke 正常，再跑论文参数版本：

```bash
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics a,b,c,d,e,f,g
```

### 3. 跑真实链 gas 实验

先启动 Ganache：

```bash
ganache \
  --server.host 127.0.0.1 \
  --server.port 7545 \
  --chain.chainId 1337 \
  --wallet.totalAccounts 10
```

再执行：

```bash
./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
```

### 4. 查看实验结果

所有实验结果都会写到：

- `results/paper_tests/*.csv`
- `results/paper_tests/*.json`

例如：

- `results/paper_tests/A_upload.csv`
- `results/paper_tests/B_prove.csv`
- `results/paper_tests/C_verify.csv`
- `results/paper_tests/H_audit_gas.csv`
- `results/paper_tests/I_transfer_gas.csv`

### 5. 跑单元测试确认系统没有回归

```bash
./.venv/bin/pytest -q
```

### 6. 推荐的最小测试路径

如果你只想快速验证“系统和实验都能跑”，最少执行这几步：

```bash
bash scripts/setup_paper_env.sh
DUPMIX_PAIRING_BACKEND=paper_pbc ./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode smoke --metrics all
./.venv/bin/python scripts/paper_tests/test_H_audit_gas.py
./.venv/bin/python scripts/paper_tests/test_I_transfer_gas.py
./.venv/bin/pytest -q
```

## 结果输出

结果保存在：

- `results/paper_tests/*.csv`
- `results/paper_tests/*.json`

可比性判定建议：

- `comparable=true` 才能作为论文对照结果使用
- `comparable=false` 只用于工程回归和趋势观察

自动生成“论文值 vs 实测值”对比报告：

```bash
./.venv/bin/python scripts/paper_tests/build_report.py
```

输出文件：

- `results/paper_tests/paper_vs_measured_summary.csv`
- `results/paper_tests/paper_vs_measured_summary.json`
- `results/paper_tests/paper_vs_measured_report.md`

已生成的真实链 gas 文件包括：

- [H_audit_gas.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/H_audit_gas.csv)
- [I_transfer_gas.csv](/home/zsw/codes/Dup_Mix2/results/paper_tests/I_transfer_gas.csv)

## 验证

运行单元测试：

```bash
./.venv/bin/pytest -q
```

当前状态：

- 严格双线性配对后端已启用
- `pairing_strict=True`
- `FULL_REPRO` 环境检查可通过
- 真实链 `H/I` gas 脚本可运行
- 全量测试通过
