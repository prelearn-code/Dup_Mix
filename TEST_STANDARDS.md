# Test Standards

本文件只保留论文复现所需的核心测试口径。

## 固定参数

- 块大小：`4 KiB`
- 每块 sector 数：`128`
- 重复率：`75%`
- 平均重复次数：`1000`

## 离线指标

- A 上传阶段
  - 指标：`avg_tag_ms`、`avg_auth_ms`
  - 变量：块数 `1000 ~ 10000`

- B 审计证明
  - 指标：`avg_prove_ms`
  - 变量：challenge blocks `100 ~ 1000`
  - 关键论文点：`z=300`、`z=460`

- C 审计验证
  - 指标：`avg_verify_ms`
  - 变量：challenge blocks `100 ~ 1000`
  - 关键论文点：`z=300`、`z=460`

- D 加密 / 解密
  - 指标：`avg_encrypt_ms`、`avg_decrypt_ms`
  - 变量：私密数据比例 `w`
  - 固定块数：`5000`

- E 动态更新
  - 指标：`avg_update_ms`
  - 代表操作：插入
  - 关键论文点：`1000` 个更新块

- F 通信
  - 指标：`upload_bytes`、`audit_comm_bytes`

- G 文件级去重
  - 指标：`file_tag_ms`、`prove_ms`、`verify_ms`、`encrypt_ms`
  - 固定：`2000 x 4 KiB`
  - 私密比例：`50%`
  - challenge blocks：`460`

## 链上指标

- H 审计 gas
  - 指标：`challenge_gas`、`prove_gas`、`verify_gas`

- I 所有权转移 gas
  - 指标：`request_gas`、`owner_verify_gas`、`csp_update_gas`、`finalize_gas`

## 严格复现条件

必须满足：

- `DUPMIX_PAIRING_BACKEND=paper_pbc`
- `pairing_strict=True`
- Ganache 可访问
- 本地 `solc` 可用

检查命令：

```bash
DUPMIX_PAIRING_BACKEND=paper_pbc ./.venv/bin/python scripts/check_paper_env.py --check-pbc-property
```
