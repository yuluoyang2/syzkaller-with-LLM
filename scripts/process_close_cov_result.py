#!/usr/bin/env python3
#process_close_cov_result.py
from pathlib import Path
import json
import os
from openai import OpenAI
from dotenv import load_dotenv
project_root = Path.cwd().parent.parent
load_dotenv(project_root / ".env")
API_KEY = os.getenv("QWEN_API_KEY")
client = OpenAI(
    api_key=API_KEY,
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
)


def main():
    # Step 1: 加载地址 -> 源码信息映射
    # 字典：地址 -> "文件路径\n函数名\n源码行"
    close_addr2funcname_and_filepath = {}
    func2addr_path = project_root / "workdir" / "func2addr_info.json"

    if not func2addr_path.exists():
        print(f"Warning: {func2addr_path} not found. Skipping function info parsing.")
        return

    with open(func2addr_path, "r") as f:
        data = json.load(f)
    for entry in data:
        funcname = entry.get("funcname", "")
        filepath = entry.get("filepath", "")
        for line_info in entry.get("source_lines", []):
            source_code = line_info.get("source", "")
            addresses = line_info.get("addresses", [])

            for addr in addresses:
                info = f"{filepath}\n{funcname}\n{source_code}"
                close_addr2funcname_and_filepath[addr] = info

    # Step 2: 处理字典结果，添加源码信息
    cov_path = project_root / "syzkaller" / "scripts" / "close_cov_results.jsonl"
    if not cov_path.exists():
        return []
    results = []
    with open(cov_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            rec = json.loads(line)
            calls = rec.get("call_sequence", [])
            for addr in rec.get("covered_close_points", []):
                if addr in close_addr2funcname_and_filepath:
                    fp, fn, src = close_addr2funcname_and_filepath[addr].split('\n', 2)
                    results.append({
                        "call_sequence": calls,
                        "filepath": fp,
                        "function": fn,
                        "source_code": [src]  
                    })
    # 合并相同上下文的源码行
    merged = {}
    for item in results:
        call_seq = tuple(
            (c["syscall"], tuple(c.get("args", [])))
            for c in item["call_sequence"]
        )
        key = (
            call_seq,
            item["filepath"],
            item["function"]
        )
        if key not in merged:
               merged[key] = {
                "call_sequence": item["call_sequence"],
                "filepath": item["filepath"],
                "function": item["function"],
                "source_code": []
            }
        for line in item["source_code"]:
            if line not in merged[key]["source_code"]:
                merged[key]["source_code"].append(line)

    merged_results = list(merged.values())
    # 保存结果到 JSON 文件
    with open("./close_cov_result_with_source.json", "w") as f:
        json.dump(merged_results, f, indent=2, ensure_ascii=False)


    # Step 3: 生成 LLM 提示词
    prompt_output_path = project_root / "workdir" / "llm_prompts.txt"
    with open(project_root/"workdir"/"target_function.txt", "r") as f:
        target_function = f.read().strip()
    prompt = f"""
你是一名资深 Linux 内核安全研究员，专注于静态与动态可达性分析。  
你的任务是：
基于已观察到的、能够接近目标内核函数 `{target_function}` 的系统调用执行记录，
推理并给出可能进一步触发或更深入触发该目标函数的系统调用名称。

**输入信息：**

以下 JSON 记录了 fuzz 测试中已成功接近目标函数的执行轨迹。
每条记录包含：
- 系统调用序列
- 实际触达的内核函数
- 在该函数中覆盖到的源码行

{merged_results}

**环境与约束：**
- 目标内核版本:Linux v6.6 (mainline)
- Fuzzer 以 root 权限运行在虚拟机中
- 所有系统调用名称必须是 **有效的 Syzkaller 系统调用标识符**

**规则:**
- 基于内核逻辑、权限检查和调用路径可达性进行分析。
- 推荐的系统调用应当在现有执行轨迹基础上，作为补充或扩展，提升触达目标函数的概率或覆盖深度。
- 不得编造或猜测系统调用名称，所有名称必须真实存在于 Syzkaller 的系统调用规范中。

**输入格式:**
- 仅返回有效系统调用名称的 JSON 数组。
- 使用准确的 Syzkaller 系统调用命名。
- 不要包含解释、注释、Markdown、反引号或额外文本。
- 如果没有有效的系统调用，返回空数组：[]
示例输出：
["openat", "close", "unlinkat"]
"""
    with open(prompt_output_path, "w") as f:
        f.write(prompt)
    print(f"LLM prompt written to {prompt_output_path}")

    # Step 4: 与大模型交互获得推荐的系统调用名称
    response = client.chat.completions.create(
        model="qwen3-max",
        temperature=0.3,  # 分析任务用低温度更准确
        max_tokens=2048,   # 预留足够空间
        messages=[
            {'role': 'system', 'content': '你是Linux内核专家,精通系统调用与调用图分析'},
            {'role': 'user', 'content': prompt},
        ],
    )
    full_response = response.choices[0].message.content.strip()
        
    # 解析JSON
    json_str = full_response.strip()
    if json_str.startswith("```json"):
        json_str = json_str[7:].strip()
    if json_str.endswith("```"):
        json_str = json_str[:-3].strip()
    syscall_list = json.loads(json_str)
        
    if not isinstance(syscall_list, list):
        raise ValueError("返回的不是列表格式")
    tmp = project_root / "syzkaller" / "llm_syscall_names.json.tmp"
    final = project_root / "syzkaller" / "llm_syscall_names.json"
    # 原子写
    with open(tmp, "w") as f:
        json.dump(syscall_list, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, final)
if __name__ == "__main__":
    main()