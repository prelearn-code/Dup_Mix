# Reproduction Plan

当前只保留复现执行状态。

## Status

1. 环境检查
   - DONE

2. 严格双线性配对后端
   - DONE
   - 当前可见：`pairing_strict=True`

3. 真实链 gas 基准
   - DONE
   - 对应：`H`、`I`

4. 配置化论文 benchmark
   - DONE
   - 对应：`configs/paper_repro.yaml`
   - 入口：`scripts/paper_tests/run_paper_repro.py`

5. 论文结果对比报告
   - TODO

## 常用命令

```bash
./.venv/bin/python scripts/check_paper_env.py
DUPMIX_PAIRING_BACKEND=paper_pbc DUPMIX_REQUIRE_STRICT_PBC=1 ./.venv/bin/python scripts/check_pairing_backend.py
./.venv/bin/python scripts/paper_tests/run_paper_repro.py --mode full --metrics all
```
