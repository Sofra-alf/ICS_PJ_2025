import json
import sys
from typing import Dict, List, Any, Set, Tuple

def load_json_file(filename: str) -> List[Dict[str, Any]]:
    """加载JSON文件"""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"错误: 文件 '{filename}' 不存在")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"错误: 文件 '{filename}' 不是有效的JSON格式")
        print(f"JSON解析错误: {e}")
        sys.exit(1)

def compare_registers(reg1: Dict[str, int], reg2: Dict[str, int], state_idx: int) -> List[str]:
    """比较两个寄存器状态，返回差异列表"""
    diffs = []
    all_regs = set(reg1.keys()) | set(reg2.keys())
    
    for reg in sorted(all_regs):
        val1 = reg1.get(reg, 0)
        val2 = reg2.get(reg, 0)
        
        if val1 != val2:
            diffs.append(f"  寄存器 {reg}: 文件1={val1}, 文件2={val2} (差值: {val1 - val2})")
    
    return diffs

def compare_memory(mem1: Dict[str, int], mem2: Dict[str, int], state_idx: int) -> List[str]:
    """比较两个内存状态，返回差异列表"""
    diffs = []
    all_addrs = set(mem1.keys()) | set(mem2.keys())
    
    for addr in sorted(all_addrs, key=lambda x: int(x)):
        val1 = mem1.get(addr, 0)
        val2 = mem2.get(addr, 0)
        
        if val1 != val2:
            diffs.append(f"  内存地址 0x{int(addr):X}: 文件1={val1}, 文件2={val2} (差值: {val1 - val2})")
    
    return diffs

def compare_cc(cc1: Dict[str, int], cc2: Dict[str, int], state_idx: int) -> List[str]:
    """比较两个条件码状态，返回差异列表"""
    diffs = []
    
    for flag in ['ZF', 'SF', 'OF']:
        val1 = cc1.get(flag, 0)
        val2 = cc2.get(flag, 0)
        
        if val1 != val2:
            flag_name = {'ZF': '零标志', 'SF': '符号标志', 'OF': '溢出标志'}[flag]
            diffs.append(f"  条件码 {flag_name}({flag}): 文件1={val1}, 文件2={val2}")
    
    return diffs

def compare_state(state1: Dict[str, Any], state2: Dict[str, Any], state_idx: int) -> List[str]:
    """比较单个状态，返回差异列表"""
    diffs = []
    
    # 比较PC
    if state1.get('PC') != state2.get('PC'):
        diffs.append(f"  PC: 文件1={state1.get('PC')}, 文件2={state2.get('PC')}")
    
    # 比较STAT
    if state1.get('STAT') != state2.get('STAT'):
        stat_names = {1: '正常', 2: '停机', 3: '错误'}
        stat1 = state1.get('STAT', 1)
        stat2 = state2.get('STAT', 1)
        diffs.append(f"  STAT: 文件1={stat1}({stat_names.get(stat1, '未知')}), 文件2={stat2}({stat_names.get(stat2, '未知')})")
    
    # 比较条件码
    cc_diffs = compare_cc(state1.get('CC', {}), state2.get('CC', {}), state_idx)
    diffs.extend(cc_diffs)
    
    # 比较寄存器
    reg_diffs = compare_registers(state1.get('REG', {}), state2.get('REG', {}), state_idx)
    diffs.extend(reg_diffs)
    
    # 比较内存
    mem_diffs = compare_memory(state1.get('MEM', {}), state2.get('MEM', {}), state_idx)
    diffs.extend(mem_diffs)
    
    return diffs

def compare_y86_outputs(file1: str, file2: str, verbose: bool = True) -> bool:
    """
    比较两个Y86模拟器输出文件
    返回: True如果相同，False如果有差异
    """
    print(f"比较文件: {file1} 和 {file2}")
    print("=" * 60)
    
    # 加载文件
    data1 = load_json_file(file1)
    data2 = load_json_file(file2)
    
    # 检查状态数量
    if len(data1) != len(data2):
        print(f"❌ 状态数量不同: 文件1有{len(data1)}个状态, 文件2有{len(data2)}个状态")
        
        # 比较共同的部分
        common_states = min(len(data1), len(data2))
        for i in range(common_states):
            diffs = compare_state(data1[i], data2[i], i)
            if diffs:
                print(f"\n🔍 状态 {i} 存在差异:")
                for diff in diffs:
                    print(diff)
        
        return False
    
    print(f"✓ 两个文件都有 {len(data1)} 个状态")
    
    # 比较每个状态
    all_diffs = []
    different_states = 0
    
    for i in range(len(data1)):
        diffs = compare_state(data1[i], data2[i], i)
        if diffs:
            all_diffs.append((i, diffs))
            different_states += 1
    
    # 输出结果
    if different_states == 0:
        print("✅ 两个文件完全一致！")
        return True
    else:
        print(f"\n❌ 发现 {different_states}/{len(data1)} 个状态存在差异")
        
        for state_idx, diffs in all_diffs:
            print(f"\n🔍 状态 {state_idx} 的差异:")
            for diff in diffs:
                print(diff)
            
            if verbose and state_idx < len(data1) - 1:
                # 显示下一个状态的信息（如果有的话）
                print(f"  下一个状态的PC: 文件1={data1[state_idx+1].get('PC')}, 文件2={data2[state_idx+1].get('PC')}")
        
        return False

def calculate_statistics(file1: str, file2: str):
    """计算并显示两个文件的统计信息"""
    data1 = load_json_file(file1)
    data2 = load_json_file(file2)
    
    print("\n📊 统计信息:")
    print(f"文件1: {len(data1)} 个状态")
    print(f"文件2: {len(data2)} 个状态")
    
    # 计算最终状态
    if data1 and data2:
        final1 = data1[-1]
        final2 = data2[-1]
        
        print(f"\n最终状态比较:")
        print(f"  PC: 文件1={final1.get('PC')}, 文件2={final2.get('PC')}")
        print(f"  STAT: 文件1={final1.get('STAT')}, 文件2={final2.get('STAT')}")
        
        # 最终寄存器值
        reg1 = final1.get('REG', {})
        reg2 = final2.get('REG', {})
        diff_regs = {reg: (reg1.get(reg, 0), reg2.get(reg, 0)) 
                    for reg in set(reg1.keys()) | set(reg2.keys())
                    if reg1.get(reg, 0) != reg2.get(reg, 0)}
        
        if diff_regs:
            print(f"  最终寄存器差异: {len(diff_regs)} 个")
            for reg, (v1, v2) in sorted(diff_regs.items()):
                print(f"    {reg}: {v1} vs {v2}")

def main():
    """主函数：比较两个JSON文件"""
    if len(sys.argv) < 3:
        print("用法: python compare_y86.py <文件1> <文件2>")
        print("示例: python compare_y86.py output1.json output2.json")
        print("\n可选参数:")
        print("  --quiet   只显示汇总结果，不显示详细差异")
        sys.exit(1)
    
    file1 = sys.argv[1]
    file2 = sys.argv[2]
    
    # 检查是否使用安静模式
    verbose = True
    if len(sys.argv) > 3 and sys.argv[3] == '--quiet':
        verbose = False
    
    # 比较文件
    are_same = compare_y86_outputs(file1, file2, verbose)
    
    # 显示统计信息
    if not are_same and verbose:
        calculate_statistics(file1, file2)
    
    # 返回适当的退出码
    sys.exit(0 if are_same else 1)

if __name__ == "__main__":
    main()