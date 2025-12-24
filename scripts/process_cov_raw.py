#!/usr/bin/env python3
#process_cov_raw.py
from argparse import ArgumentParser
import json
from pathlib import Path

def main():

    args = ArgumentParser(description="Process coverage data for close function calls.")
    args.add_argument("cov_file", help="Path to the coverage JSON file.")
    args.add_argument("bounded_str", help="String indicating if execution is bounded.")
    args = args.parse_args()
    cov_file_path = Path(args.cov_file)
    bounded_str = args.bounded_str

    # 判断是否未达到执行上限
    is_under_bound = "bound" not in bounded_str

    # 加载目标函数地址集合
    addr_file = Path("../../workdir/result_addr_info.txt")

    with open(addr_file, "r") as f:
        close_func_addr = {line.strip() for line in f if line.strip()}

    # 读取 coverage 数据
    with open(cov_file_path, "r") as f:
        records = json.load(f)

    total_close_points = set()
    call_sequences = []

    for rec in records:
        cover_addrs = rec.get("cover", [])
        syscall_name = rec.get("syscall", "")
        args = rec.get("args", [])

        # 收集属于 close 函数的地址

        close_hits = [addr for addr in cover_addrs if addr in close_func_addr]
        if close_hits:
            total_close_points.update(close_hits)
        call_sequences.append({
            "syscall": syscall_name,
            "args": args
        })
    # 如果有命中且未达上限，写入结果
    if total_close_points and is_under_bound:
        result_entry = {
            "call_sequence": call_sequences,
            "covered_close_points": total_close_points
        }

        # 追加到 .jsonl 文件
        with open("close_cov_results.jsonl", "a") as f:
            f.write(json.dumps(result_entry, ensure_ascii=False) + "\n")

        print("write hit cov:", ", ".join(total_close_points))

    # 通知 Go 层是否命中
    if total_close_points:
        print("XXXXX REACH")

if __name__ == "__main__":
    main()