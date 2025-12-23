#!/usr/bin/env python3
# This file is called from syzkaller root path

import os
import sys
import json

def load_close_ranges(range_file_path):
    """加载 close 函数地址范围，返回 [(start, end), ...]"""
    ranges = []
    try:
        with open(range_file_path, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 3:
                    _, start_hex, end_hex = parts
                    try:
                        start = int(start_hex, 16)
                        end = int(end_hex, 16)
                        ranges.append((start, end))
                    except ValueError:
                        continue
    except FileNotFoundError:
        print(f"Warning: {range_file_path} not found. No close ranges loaded.")
    return ranges

def addr_in_any_range(addr_str, ranges):
    """判断 addr_str (如 'a1b2c3d4') 是否落在任意 [start, end) 区间内"""
    if not addr_str or not all(c in '0123456789abcdef' for c in addr_str):
        return False
    try:
        addr = int(addr_str, 16)
    except ValueError:
        return False
    for start, end in ranges:
        if start <= addr < end:
            return True
    return False

def main():
    if len(sys.argv) < 3:
        print("Usage: process_cov_raw.py <cov_file.json> <bounded_str>")
        sys.exit(1)

    cov_file_path = sys.argv[1]
    bounded_str = sys.argv[2]
    hit_bound_not_reach = "bound" not in bounded_str

    # 加载函数地址范围
    close_range_file = "../../workdir/close_func_ranges.txt"
    close_ranges = load_close_ranges(close_range_file)

    # 读取并解析 JSON coverage 文件
    try:
        with open(cov_file_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading or parsing {cov_file_path}: {e}")
        return

    if not isinstance(data, list):
        print(f"Invalid JSON format in {cov_file_path}: expected array")
        return

    total_close_points = set()

    # 检查所有 cover 地址是否命中 close 范围
    for record in data:
        cover_addrs = record.get("cover", [])
        for addr in cover_addrs:
            if addr_in_any_range(addr, close_ranges):
                total_close_points.add(addr)

    contain_close_points = len(total_close_points) > 0

    # 如果命中且未达到上限，写入结构化结果
    if contain_close_points and hit_bound_not_reach:
        result_entry = {
            "call_sequence": [
                {
                    "syscall": record.get("syscall", ""),
                    "args": record.get("args", [])
                }
                for record in data
            ],
            "close_points_covered": sorted(total_close_points),
        }

        # 使用 .jsonl 扩展名更规范
        with open("close_cov_results.jsonl", "a") as f:
            f.write(json.dumps(result_entry, ensure_ascii=False) + "\n")

        print("write hit cov:", ", ".join(sorted(total_close_points)))

    # 通知 Go 层是否命中
    if contain_close_points:
        print("XXXXX REACH")

if __name__ == "__main__":
    main()