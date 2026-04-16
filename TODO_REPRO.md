# TODO Repro

本文件用于跟踪“让当前实现尽量逼近论文实验结果”所需的具体改造项。

| 文件 | 函数 | 修改目标 | 验收标准 |
| --- | --- | --- | --- |
| `/home/zsw/codes/Dup_Mix2/src/protocol.py` | `audit_req` | 去掉当前 `z_value = min(3, max(1, n))` 的简化逻辑，改为由实验参数显式传入挑战块数，并支持论文关键值 `300`、`460`。 | 运行审计实验时，日志和结果文件中的 `z` 与输入参数完全一致；不再出现固定上限 `3`。 |
| `/home/zsw/codes/Dup_Mix2/src/protocol.py` | `proof_gen` | 按论文算法重新核对 proof 组成，补齐链上验证所需的证明字段与序列化格式，避免只返回当前简化版 `indices/coeffs/P/sigma_c/Y_agg`。 | proof 对象字段与论文算法定义一致；链上合约可以直接消费 proof 数据，不依赖本地重算补全。 |
| `/home/zsw/codes/Dup_Mix2/src/protocol.py` | `verify_proof_protocol` | 将当前“本地重算并比较”的验证主路径改为“提交 proof 到链上，由合约完成验证与结算”；本地逻辑只保留预检查或调试用途。 | `C_verify` 实验可以统计真实链上验证时间和 gas；主验证结果来自链上回执或合约状态，而不是 Python 布尔比较。 |
| `/home/zsw/codes/Dup_Mix2/src/crypto.py` | `authgen` | 逐项核对认证器生成公式，确认 `y_i / Y_i / sigma_i` 与论文完全一致，去掉为工程简化加入的近似路径。 | 用论文公式逐项推导可得到与代码一致的中间量；单元测试覆盖认证器生成正确性。 |
| `/home/zsw/codes/Dup_Mix2/src/crypto.py` | `aggregate_authenticator` | 使聚合认证器计算严格匹配论文中的 Prove/Verify 定义，不提前做本地简化聚合。 | 对同一 challenge，聚合结果可被链上验证逻辑直接使用；与论文公式核对无遗漏项。 |
| `/home/zsw/codes/Dup_Mix2/src/crypto.py` | `verify_upload_authenticator` | 复核上传阶段认证器验证公式，确保使用严格配对后端时的验证关系与论文一致。 | 在 `DUPMIX_REQUIRE_STRICT_PBC=1` 下上传认证器验证通过；篡改任一关键字段时验证失败。 |
| `/home/zsw/codes/Dup_Mix2/src/crypto.py` | `pairing` | 继续收口严格双线性配对路径，避免任何 fallback 结果混入论文复现实验。 | 论文复现模式下结果元数据中始终显示 `pairing_strict=True`；若严格后端不可用则实验直接失败。 |
| `/home/zsw/codes/Dup_Mix2/contracts/AuditSystem.sol` | `benchmarkSubmitProof` | 将当前只写入 `proofHash` 的轻量逻辑改为提交完整或半完整证明结构，体现论文 Prove 阶段的链上写入成本。 | `H` 中的 `prove_gas` 明显高于当前轻量版本；交易输入数据与 proof 结构一一对应。 |
| `/home/zsw/codes/Dup_Mix2/contracts/AuditSystem.sol` | `benchmarkVerifyProofAndSettle` | 把论文中的 challenge-dependent 验证计算搬到链上，不再仅接收 `bool isValid` 做状态结算。 | `verify_gas` 来自真实验证计算；删除或停用“只传 `isValid`”的简化 benchmark 路径。 |
| `/home/zsw/codes/Dup_Mix2/contracts/AuditSystem.sol` | `requestTransfer` | 复核交易请求阶段写入字段，尽量贴近论文中的身份信息与预付费用处理。 | `I request_gas` 与论文量级保持接近，且输入字段可说明与论文交易阶段对应关系。 |
| `/home/zsw/codes/Dup_Mix2/contracts/AuditSystem.sol` | `benchmarkVerifyTransferOwner` | 不再只校验 `fromOwner` 地址和置位布尔值，补充原始所有者身份验证所需的真实字段与校验动作。 | `owner_verify_gas` 明显高于当前简化值，并与论文阶段动作语义一致。 |
| `/home/zsw/codes/Dup_Mix2/contracts/AuditSystem.sol` | `benchmarkCspUpdateTransfer` | 增加 CSP 对所有权元数据的真实更新写入，而不是只置位 `transferCspUpdated`。 | `csp_update_gas` 体现链上状态更新成本；链上可读取更新后的 ownership 元数据。 |
| `/home/zsw/codes/Dup_Mix2/contracts/AuditSystem.sol` | `benchmarkFinalizeTransfer` | 复核最终结算阶段，确保退款、惩罚和状态落账过程与论文描述一致。 | `finalize_gas` 可解释为论文最后阶段的链上成本；成功/失败两条分支行为清晰。 |
| `/home/zsw/codes/Dup_Mix2/src/chain.py` | `connect_chain` 及真实链交互封装 | 区分 mock 链和真实 Ganache 路径，论文复现模式默认走真实链，不允许静默回退到 mock。 | 在复现模式下，如果 RPC 不可用则直接报错；结果文件记录 `chain_mode=real`。 |
| `/home/zsw/codes/Dup_Mix2/src/chain.py` | 部署与交易回执相关函数 | 统一采集交易 hash、receipt、`gasUsed`、区块号和状态，作为 H/I 指标的唯一数据来源。 | H/I 结果文件全部来自真实 receipt；不再混用估算值或本地状态。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/benchmarks.py` | `build_runtime` | 去掉 `force_mock=True` 的论文实验默认路径，增加 `mock|real` 可配置运行模式。 | 论文 full 模式默认使用真实链；日志与结果文件明确写出 `chain_mode`。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/benchmarks.py` | `bench_b_prove` | 把 challenge 参数改成论文关键点，并保证测量的是论文定义的 Prove 阶段工作量。 | `B` 默认支持 `z=300,460`；结果与论文图 4(b) 可直接对照。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/benchmarks.py` | `bench_c_verify` | 将当前本地 verify 时间测量改为论文口径的验证流程，必要时拆分离线验证时间和链上验证时间。 | `C` 的输出字段能明确说明是链上验证还是总验证时间；可与论文图 4(c) 对照。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/benchmarks.py` | `bench_e_update` | 将更新实验固定为论文使用的更新类型与规模，默认跑 `1000` 次更新。 | `E` full 模式输出 `1000` updates 结果；与论文图 5(c) 口径一致。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/benchmarks.py` | `bench_f_communication` | 不再用 Python 对象大小近似通信开销，改为按协议字段逐项统计消息字节数。 | `F` 的 upload/audit 开销可拆解到字段级别，并能说明与论文图 6 的对应关系。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/benchmarks.py` | `bench_g_file_dedup` | 将文件级去重实验参数改成论文配置：`2000 × 4KiB`、`w=50%`、`z=460`。 | `G` full 模式固定输出论文口径结果；字段命名与论文表 V / 图 7 对应。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/test_H_audit_gas.py` | `main` / gas 测量主流程 | 用真实 proof 提交和真实链上验证交易替换当前轻量 benchmark，保证 `Challenge/Prove/Verify` 三阶段都来自真实 receipt。 | `H_audit_gas.csv` 中所有 gas 值来自交易 receipt，且每个阶段对应论文图 8 的一列。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/test_I_transfer_gas.py` | `main` / gas 测量主流程 | 用更完整的所有权交易阶段数据替换当前布尔置位路径，保证四阶段 gas 与论文图 9 更一致。 | `I_transfer_gas.csv` 可逐阶段解释输入、状态变化和 gas 来源。 |
| `/home/zsw/codes/Dup_Mix2/configs/paper_repro.yaml` | `full` 配置 | 将 full 模式固定为论文规模：`4 KiB`、`128 sectors`、重复率 `75%`、`B/C z=300,460`、`D 5000 blocks`、`E 1000 updates`、`G 2000×4KiB`、平均 `1000` 次。 | 运行 `--mode full` 时，不再沿用 smoke/demo 参数；配置文件能直接映射到论文实验段落。 |
| `/home/zsw/codes/Dup_Mix2/scripts/paper_tests/run_paper_repro.py` | 运行入口 | 强制区分 `smoke` 与 `full`；full 模式输出“是否可与论文直接比较”的元信息。 | 结果目录中包含运行元数据，如 `chain_mode`、`pairing_strict`、`paper_scale`、`comparable`。 |
| `/home/zsw/codes/Dup_Mix2/README.md` | 实验说明相关章节 | 明确标注哪些结果是 smoke、哪些是 full、哪些可以与论文直接比较，避免混淆。 | 新同学按文档运行时，能清楚区分“演示跑通”和“论文复现”。 |
| `/home/zsw/codes/Dup_Mix2/EXPERIMENT_FLOW.md` | 结果说明相关章节 | 补充“当前实现与论文仍有差异”的说明，并在每一步标记使用的运行模式与数据来源。 | 实验流程文档能直接解释为什么某些结果偏差大，不会误导为已完全复现。 |

## 建议执行顺序

1. 先改 `src/protocol.py` 与 `contracts/AuditSystem.sol`，把 Verify 主路径和链上负载改对。
2. 再改 `src/chain.py`、`scripts/paper_tests/test_H_audit_gas.py`、`scripts/paper_tests/test_I_transfer_gas.py`，确保 gas 统计全部来自真实链。
3. 再改 `scripts/paper_tests/benchmarks.py` 与 `configs/paper_repro.yaml`，把 A-G 的参数和统计口径收敛到论文。
4. 最后更新 `README.md` 和 `EXPERIMENT_FLOW.md`，同步说明哪些指标已经进入可比状态。
