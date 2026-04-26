import os

# ==========================================
# 第一部分：前 10KB 文件的独特英文段落
# ==========================================
base_unique_text = """DOCUMENT ID: SEC-AUDIT-2026
TITLE: Architecture and Protocol Implementation Report
SUBJECT: Intelligent System Analysis

[SECTION 1: EXECUTIVE SUMMARY]
This document outlines the core security architecture, cryptographic implementations, and data integrity protocols for the upcoming autonomous network deployment. The primary objective is to ensure resilience against advanced persistent threats, while maintaining high-efficiency telemetry processing for edge devices. The system architecture heavily relies on containerized microservices, ensuring isolated execution environments for both analytical engines and high-performance control loops. 

[SECTION 2: CRYPTOGRAPHIC STANDARDS]
As the threat landscape evolves, reliance on traditional public-key infrastructure is insufficient. Extensive cryptanalysis has demonstrated vulnerabilities to sufficiently large computational ensembles. Consequently, this architecture deprecates legacy implementations in favor of advanced lattice-based signature algorithms. Specifically, next-generation protocols have been integrated into the core authentication handshake.

[SECTION 3: STORAGE AND DATA INTEGRITY]
A critical challenge in managing massive fleets is the volume of redundant telemetry generated. To address this, we have implemented a secure deduplication mechanism tailored for decentralized storage environments. Traditional deduplication poses severe privacy risks; thus, our approach utilizes convergent encryption. Smart Contracts act as trustless arbiters, periodically issuing cryptographic challenges to the storage nodes.

[SECTION 4: SYSTEM TELEMETRY LOGS]
The following entries represent the routine automated checks performed during the latest simulation cycle. They verify memory integrity and protocol compliance across all active nodes.
"""

# ==========================================
# 第二部分：用于补充到 12KB 的全新英文段落
# ==========================================
extra_unique_text = """
[SECTION 5: SYSTEM DEPLOYMENT PHASES]
Moving from theoretical models to real-world application, the immediate roadmap focuses on the physical deployment of a security demonstration system. The chosen location provides an ideal testing ground for evaluating signal degradation, urban canyon effects on spatial coordination, and the resilience of our mesh networking protocols under physical interference.

[SECTION 6: AI AGENT ORCHESTRATION]
To manage the immense complexity of the demonstration, manual monitoring is highly inefficient. Therefore, the command-and-control infrastructure will integrate advanced AI Agent technology. By utilizing multi-agent conversations, distinct AI models act as specialized network administrators to handle complex decision-making processes regarding dynamic routing and threat mitigation strategies.
"""

# 用于精确填充大小的重复日志短句
log_line = "[LOG] System heartbeat nominal. Cryptographic keys rotated successfully. Ledger synced.\n"

def create_files():
    # ---------------------------------------------------------
    # 步骤 1：生成精确的 10KB (10240 Bytes) 文件
    # ---------------------------------------------------------
    content_10kb = base_unique_text.encode('utf-8')
    log_bytes = log_line.encode('utf-8')
    
    # 计算需要多少行日志来填满剩下的空间
    remaining_bytes_10 = 10240 - len(content_10kb)
    if remaining_bytes_10 > 0:
        repeat_count = remaining_bytes_10 // len(log_bytes)
        content_10kb += log_bytes * repeat_count
        # 用等号填充最后除不尽的零头，确保一字节不差
        padding = remaining_bytes_10 % len(log_bytes)
        content_10kb += b"=" * padding

    # 以 wb (二进制写入) 模式保存，屏蔽操作系统的换行符差异
    with open("File1_10KB.txt", "wb") as f:
        f.write(content_10kb)

    # ---------------------------------------------------------
    # 步骤 2：生成精确的 12KB (12288 Bytes) 文件
    # ---------------------------------------------------------
    # 完全包含前一个文件的内容，加上新内容
    content_12kb = content_10kb + extra_unique_text.encode('utf-8')
    
    # 继续用日志行填充到 12288 字节
    remaining_bytes_12 = 12288 - len(content_12kb)
    if remaining_bytes_12 > 0:
        repeat_count = remaining_bytes_12 // len(log_bytes)
        content_12kb += log_bytes * repeat_count
        padding = remaining_bytes_12 % len(log_bytes)
        content_12kb += b"=" * padding

    with open("File2_12KB.txt", "wb") as f:
        f.write(content_12kb)

    print("✅ 成功生成文件：")
    print(f" - File1_10KB.txt ({os.path.getsize('File1_10KB.txt')} Bytes)")
    print(f" - File2_12KB.txt ({os.path.getsize('File2_12KB.txt')} Bytes)")

if __name__ == "__main__":
    create_files()