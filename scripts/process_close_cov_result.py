#!/usr/bin/env python3

from pathlib import Path
import subprocess

# 假设该脚本位于 syzkaller/ 目录下，project_root 是其父目录
project_root = Path(__file__).parent.parent.resolve()

# 全局字典：地址 -> "文件路径\n函数名\n源码行"
close_addr2funcname_and_filepath = {}


def parse_func2addr_info():
    """
    解析 func2addr_info.txt，构建地址到源码信息的映射。
    格式示例：
        ----- funcname
        ext4_write_inode
        ----- filepath
        fs/ext4/inode.c
        ----- source
        static int ext4_write_inode(struct inode *inode, struct writeback_control *wbc)
        ----- addresses
        ffffffff816a6500
        ffffffff816a65a5
    """
    func2addr_path = project_root / "line2addr" / "func2addr_info.txt"

    if not func2addr_path.exists():
        print(f"Warning: {func2addr_path} not found. Skipping function info parsing.")
        return

    curr_func_name = ""
    curr_file_path = ""
    curr_source = ""
    reading_mode = None  # 'func', 'file', 'source', 'addrs'

    with func2addr_path.open("r") as f:
        for line in f:
            line = line.rstrip('\n\r')
            if line == "----- funcname":
                reading_mode = 'func'
                curr_func_name = ""
            elif line == "----- filepath":
                reading_mode = 'file'
                curr_file_path = ""
            elif line == "----- source":
                reading_mode = 'source'
                curr_source = ""
            elif line == "----- addresses":
                reading_mode = 'addrs'
            else:
                if reading_mode == 'func':
                    curr_func_name = line
                elif reading_mode == 'file':
                    curr_file_path = line
                elif reading_mode == 'source':
                    curr_source = line
                elif reading_mode == 'addrs':
                    stripped = line.strip()
                    if stripped and all(c in '0123456789abcdef' for c in stripped):
                        addr = stripped
                        info = f"{curr_file_path}\n{curr_func_name}\n{curr_source}"
                        close_addr2funcname_and_filepath[addr] = info


def collect_close_cov_info():
    """
    解析 close_cov_result.txt（新格式），提取每个命中的程序：
      - 系统调用序列
      - 命中的 close 地址列表
    """
    cov_result_path = project_root / "syzkaller" / "close_cov_result.txt"

    if not cov_result_path.exists():
        return []

    with cov_result_path.open("r") as f:
        lines = [line.rstrip('\n\r') for line in f.readlines()]

    results = []
    call_sequence = []
    covered_points = []
    mode = None  # None, 'calls', 'covers'

    for line in lines:
        if line == "----- call sequence":
            mode = 'calls'
            call_sequence = []
            covered_points = []
        elif line == "----- close points covered":
            mode = 'covers'
        elif line == "=====":
            # 结束一个记录块
            if call_sequence or covered_points:
                results.append((call_sequence.copy(), covered_points.copy()))
            call_sequence = []
            covered_points = []
            mode = None
        else:
            stripped = line.strip()
            if not stripped:
                continue
            if mode == 'calls':
                call_sequence.append(stripped)
            elif mode == 'covers':
                # 只保留合法十六进制地址（以 f 开头）
                if stripped.startswith('f') and all(c in '0123456789abcdef' for c in stripped):
                    covered_points.append(stripped)

    # 处理文件末尾没有 ===== 的情况
    if call_sequence or covered_points:
        results.append((call_sequence, covered_points))

    return results


def formulate_program_cov_info_for_llm(close_cov_info):
    """
    将命中信息格式化为 LLM 可读的文本。
    """
    if not close_cov_info:
        return ""

    final_result = ""
    for program_id, (call_seq, cov_seq) in enumerate(close_cov_info, start=1):
        # 系统调用序列
        call_desc = f"Program {program_id} system call sequence:\n"
        for i, call in enumerate(call_seq):
            call_desc += f"({i}) {call}\n"

        # 覆盖信息（带源码上下文）
        cov_desc = f"Program {program_id} hit the following close coverage points:\n"
        for addr in cov_seq:
            if addr in close_addr2funcname_and_filepath:
                info = close_addr2funcname_and_filepath[addr]
                cov_desc += f"Address {addr}:\n{info}\n"
            else:
                cov_desc += f"Address {addr}: <function/file info not found>\n"

        final_result += call_desc + cov_desc + "\n"

    return final_result


def main():
    # Step 1: 加载地址 -> 源码信息映射
    parse_func2addr_info()

    # Step 2: 解析 close_cov_result.txt
    close_cov_info = collect_close_cov_info()

    if not close_cov_info:
        print("No close coverage hits found. Skipping LLM analysis.")
        return

    # Step 3: 生成 LLM 输入
    llm_input_path = project_root / "ChatAnalyzer" / "close_cov_prog_source_code.txt"
    llm_input = formulate_program_cov_info_for_llm(close_cov_info)

    with llm_input_path.open("w") as f:
        f.write(llm_input)

    # Step 4: 调用 LLM 分析
    chat_analyzer_dir = project_root / "ChatAnalyzer"
    chat_analyzer_dir.mkdir(exist_ok=True)  # 防止目录不存在

    print("Triggering LLM analysis via 'close ask'...")
    result = subprocess.run(
        ["python3", "chat_interface.py", "close_ask"],
        cwd=str(chat_analyzer_dir),
        capture_output=True,
        text=True,
        env=None  # 使用当前环境
    )

    print("LLM analysis stderr:", result.stderr)
    print("LLM analysis stdout:", result.stdout)

    # Step 5: 清空结果文件（避免重复分析）
    try:
        (project_root / "ChatAnalyzer" / "close_cov_prog_source_code.txt").write_text("")
        (project_root / "syzkaller" / "close_cov_result.txt").write_text("")
    except Exception as e:
        print("Warning: failed to truncate files:", e)


if __name__ == "__main__":
    main()