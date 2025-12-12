#!/usr/bin/env python3
# This file is called from syzkaller root path

import os
import sys

def is_hex_address(line: str) -> bool:
    """判断一行是否为有效的内核地址（如 ffffffff8109b0f7）"""
    line = line.strip()
    if not line:
        return False
    return line.startswith('f') and all(c in '0123456789abcdef' for c in line)

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
    """判断 addr_str 是否落在任意一个 [start, end) 区间内"""
    if not (addr_str.startswith('f') and all(c in '0123456789abcdef' for c in addr_str)):
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
        print("Usage: process_cov_raw.py <cov_file> <bounded_str>")
        sys.exit(1)

    cov_file_path = sys.argv[1]
    bounded_str = sys.argv[2]
    hit_bound_not_reach = "bound" not in bounded_str

    # 加载函数地址范围
    close_range_file = "../../line2addr/close_func_ranges.txt"
    close_ranges = load_close_ranges(close_range_file)

    # 读取 coverage 文件
    try:
        with open(cov_file_path, "r") as f:
            lines = [line.rstrip('\n\r') for line in f.readlines()]
    except Exception as e:
        print(f"Error reading {cov_file_path}: {e}")
        return

    # 解析 syscall blocks
    current_syscall = None
    syscall_blocks = []  # list of (syscall_line, [cover_addresses])
    current_covers = []

    for line in lines:
        if line == "":
            if current_syscall is not None:
                syscall_blocks.append((current_syscall, current_covers))
                current_syscall = None
                current_covers = []
        elif is_hex_address(line):
            current_covers.append(line)
        else:
            if current_syscall is not None:
                syscall_blocks.append((current_syscall, current_covers))
            current_syscall = line
            current_covers = []

    if current_syscall is not None:
        syscall_blocks.append((current_syscall, current_covers))

    # 收集所有命中的地址，用 range 判断是否属于 close 函数
    total_close_points = set()
    for _, covers in syscall_blocks:
        for addr in covers:
            if addr_in_any_range(addr, close_ranges):
                total_close_points.add(addr)

    contain_close_points = len(total_close_points) > 0

    # 如果命中且未达到上限，写入结果
    if contain_close_points and hit_bound_not_reach:
        call_sequence = "".join(f"{sc}\n" for sc, _ in syscall_blocks)
        close_points_str = "\n".join(sorted(total_close_points))

        final_result = (
            "----- call sequence\n"
            + call_sequence +
            "----- close points covered\n"
            + close_points_str +
            "\n=====\n"
        )

        print("write hit cov:", close_points_str)
        with open("./close_cov_result.txt", "a") as f:
            f.write(final_result)

    # 删除原始 coverage 文件
    try:
        os.remove(cov_file_path)
    except Exception as e:
        print(f"Warning: failed to remove {cov_file_path}: {e}")

    # 通知 Go 层是否命中
    if contain_close_points:
        print("XXXXX REACH")

if __name__ == "__main__":
    main()