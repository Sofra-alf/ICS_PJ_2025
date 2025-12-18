"""
Y86-64 指令集模拟器

本模拟器实现了完整的 Y86-64 指令集架构,支持:
- 11 种指令类型 (halt, nop, 数据传送, 算术运算, 跳转, 函数调用, 栈操作)
- 15 个通用寄存器 (rax-r14)
- 条件码 (ZF, SF, OF)
- 状态追踪和 JSON 输出

作者: [Your Name]
日期: 2025
"""

import sys
import json


class Y86_Simulator:
    """Y86-64 处理器模拟器"""

    def __init__(self):
        """初始化模拟器状态"""
        # ============ 处理器核心状态 ============
        self.PC = 0                    # 程序计数器
        self.registers = [0] * 15      # 15个通用寄存器 (rax-r14)
        self.memory = {}               # 内存 (字典实现,按需分配)

        # ============ 条件码 ============
        self.ZF = 1                    # 零标志 (Zero Flag)
        self.SF = 0                    # 符号标志 (Sign Flag)
        self.OF = 0                    # 溢出标志 (Overflow Flag)

        # ============ 状态码 ============
        # 1: AOK (正常), 2: HLT (停机), 3: ADR (地址错误), 4: INS (非法指令)
        self.status = 1

        # ============ 状态追踪 ============
        self.states = []               # 状态历史记录
        self.last_state = None         # 上一个状态(用于去重)
        self.step_count = 0            # 已执行步数
        self.max_steps = 10000         # 最大执行步数(防止死循环)

        # ============ 指令分发表 ============
        # 将操作码映射到对应的处理函数
        self.head_map = {
            0x0: self.halt,           # 停机指令
            0x1: self.nop,            # 空操作
            0x2: self.rrmove_comv,    # 寄存器传送/条件传送
            0x3: self.irmovq,         # 立即数传送
            0x4: self.rmmovq,         # 寄存器到内存
            0x5: self.mrmovq,         # 内存到寄存器
            0x6: self.OPq,            # 算术运算
            0x7: self.jump,           # 条件跳转
            0x8: self.call,           # 函数调用
            0x9: self.ret,            # 函数返回
            0xA: self.pushq,          # 压栈
            0xB: self.popq            # 出栈
        }

    # ========================================================================
    # 第一部分: 基础工具函数
    # ========================================================================

    # ---------------- 内存访问 ----------------

    def get_memory(self, address):
        """读取单字节内存"""
        if address < 0:
            return None
        return self.memory.get(address, 0)

    def get_byte(self, address):
        """读取单字节(带异常处理)"""
        result = self.get_memory(address)
        return result & 0xFF if result is not None else 0

    def get_8byte(self, address):
        """读取8字节(小端序)"""
        result = 0
        for i in range(8):
            byte = self.get_byte(address + i)
            result |= (byte << (i * 8))
        return result

    def write_8byte(self, address, value):
        """写入8字节到内存(小端序)

        Args:
            address: 目标地址
            value: 要写入的64位值

        Returns:
            bool: 是否写入成功
        """
        if address < 0:
            self.status = 3  # 地址错误
            return False
        for i in range(8):
            byte = (value >> (i * 8)) & 0xFF
            self.memory[address + i] = byte
        return True

    # ---------------- 位操作辅助函数 ----------------

    def get_front4bit(self, address):
        """获取字节的高4位"""
        byte = self.get_byte(address)
        return (byte >> 4) & 0xF

    def get_back4bit(self, address):
        """获取字节的低4位"""
        byte = self.get_byte(address)
        return byte & 0xF

    # ---------------- 寄存器访问 ----------------

    def get_register(self, reg_num):
        """安全地读取寄存器值

        Args:
            reg_num: 寄存器编号 (0-14), 15表示无寄存器

        Returns:
            int: 寄存器值
        """
        if reg_num > 15:
            self.status = 4  # 非法寄存器编号
            return 0
        if reg_num == 15:  # 0xF 表示无寄存器
            return 0
        return self.registers[reg_num]

    def set_register(self, reg_num, value):
        """安全地设置寄存器值

        Args:
            reg_num: 寄存器编号 (0-14), 15表示无寄存器
            value: 要设置的值
        """
        if reg_num > 15:
            self.status = 4  # 非法寄存器编号
            return
        if reg_num < 15:  # 0xF 表示无寄存器,不设置
            # 确保值在64位范围内
            self.registers[reg_num] = value & 0xFFFFFFFFFFFFFFFF

    # ---------------- 算术辅助函数 ----------------

    def add(self, a, b):
        """64位无符号加法"""
        return (a + b) & 0xFFFFFFFFFFFFFFFF

    def sub(self, a, b):
        """64位无符号减法"""
        return (a - b) & 0xFFFFFFFFFFFFFFFF

    def to_signed(self, value):
        """将64位无符号数转换为有符号数

        用于状态输出时的格式转换
        """
        if value >= (1 << 63):  # 最高位为1
            return value - (1 << 64)
        return value

    # ---------------- 条件码检查 ----------------

    def check_condition(self, func_code):
        """根据功能码检查条件是否满足

        用于条件传送(cmovXX)和条件跳转(jXX)指令

        Args:
            func_code: 功能码 (0x0-0x6)
                0x0: 无条件
                0x1: le (<=)
                0x2: l  (<)
                0x3: e  (==)
                0x4: ne (!=)
                0x5: ge (>=)
                0x6: g  (>)

        Returns:
            True/False: 条件是否满足
            None: 非法功能码
        """
        if func_code == 0x0:    # 无条件
            return True
        elif func_code == 0x1:  # le: (SF^OF)|ZF
            return (self.SF ^ self.OF) | self.ZF
        elif func_code == 0x2:  # l: SF^OF
            return self.SF ^ self.OF
        elif func_code == 0x3:  # e: ZF
            return self.ZF
        elif func_code == 0x4:  # ne: ~ZF
            return not self.ZF
        elif func_code == 0x5:  # ge: ~(SF^OF)
            return not (self.SF ^ self.OF)
        elif func_code == 0x6:  # g: ~(SF^OF)&~ZF
            return not (self.SF ^ self.OF) and not self.ZF
        else:
            return None  # 非法功能码

    # ========================================================================
    # 第二部分: Y86-64 指令实现
    # ========================================================================

    # ---------------- 控制指令 ----------------

    def halt(self):
        """halt: 停机指令"""
        self.status = 2

    def nop(self):
        """nop: 空操作指令"""
        self.PC += 1

    # ---------------- 数据传送指令 ----------------

    def rrmove_comv(self):
        """rrmovq/cmovXX: 寄存器间传送/条件传送

        格式: 2fn rA rB
        功能: if (cond) rB = rA
        """
        func = self.get_back4bit(self.PC)
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)

        con = self.check_condition(func)
        if con is None:  # 非法功能码
            self.status = 4
            self.PC += 2
            return

        if con:
            self.set_register(regB, self.get_register(regA))

        self.PC += 2

    def irmovq(self):
        """irmovq: 立即数传送到寄存器

        格式: 30 F rB V
        功能: rB = V
        """
        regB = self.get_back4bit(self.PC + 1)
        value = self.get_8byte(self.PC + 2)
        self.set_register(regB, value)
        self.PC += 10

    def rmmovq(self):
        """rmmovq: 寄存器传送到内存

        格式: 40 rA rB D
        功能: M[rB + D] = rA
        """
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)
        displacement = self.get_8byte(self.PC + 2)

        address = self.add(self.get_register(regB), displacement)
        value = self.get_register(regA)
        self.write_8byte(address, value)
        self.PC += 10

    def mrmovq(self):
        """mrmovq: 内存传送到寄存器

        格式: 50 rA rB D
        功能: rA = M[rB + D]
        """
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)
        displacement = self.get_8byte(self.PC + 2)

        address = self.add(self.get_register(regB), displacement)
        if address == 0:
            self.status = 3  # 读取地址0视为错误
            self.PC += 10
            return

        value = self.get_8byte(address)
        self.set_register(regA, value)
        self.PC += 10

    # ---------------- 算术逻辑指令 ----------------

    def OPq(self):
        """OPq: 算术/逻辑运算指令

        格式: 6fn rA rB
        功能: rB = rB OP rA, 设置条件码

        支持的操作:
            0x0: addq (加法)
            0x1: subq (减法)
            0x2: andq (按位与)
            0x3: xorq (按位异或)
        """
        func = self.get_back4bit(self.PC)
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)

        valA = self.get_register(regA)
        valB = self.get_register(regB)
        result = 0

        # 执行对应操作
        if func == 0x0:     # addq
            result = self.add(valB, valA)
        elif func == 0x1:   # subq
            result = self.sub(valB, valA)
        elif func == 0x2:   # andq
            result = valB & valA
        elif func == 0x3:   # xorq
            result = valB ^ valA
        else:
            self.status = 4  # 非法功能码
            self.PC += 2
            return

        self.set_register(regB, result)

        # 设置条件码
        self.ZF = 1 if result == 0 else 0
        self.SF = 1 if (result >> 63) & 0x1 else 0

        # 溢出判断
        signA = (valA >> 63) & 0x1
        signB = (valB >> 63) & 0x1
        signR = (result >> 63) & 0x1

        if func == 0x0:  # addq: 同号相加结果异号
            self.OF = 1 if (signA == signB and signA != signR) else 0
        elif func == 0x1:  # subq: 异号相减结果异号
            self.OF = 1 if (signA != signB and signB != signR) else 0
        else:
            self.OF = 0

        self.PC += 2

    # ---------------- 控制流指令 ----------------

    def jump(self):
        """jXX: 条件跳转指令

        格式: 7fn Dest
        功能: if (cond) PC = Dest
        """
        func = self.get_back4bit(self.PC)
        destination = self.get_8byte(self.PC + 1)

        con = self.check_condition(func)
        if con is None:  # 非法功能码
            self.status = 4
            self.PC += 9
            return

        if con:
            self.PC = destination
            # 非法地址检查将在下一次 fetch() 时进行
        else:
            self.PC += 9

    def call(self):
        """call: 函数调用指令

        格式: 80 Dest
        功能: push PC+9; PC = Dest
        """
        destination = self.get_8byte(self.PC + 1)

        # 压栈返回地址
        rsp = self.get_register(4)  # rsp 是第4个寄存器
        rsp -= 8
        self.write_8byte(rsp, self.PC + 9)
        self.set_register(4, rsp)

        # 跳转
        self.PC = destination

    def ret(self):
        """ret: 函数返回指令

        格式: 90
        功能: pop PC
        """
        rsp = self.get_register(4)
        return_address = self.get_8byte(rsp)
        rsp += 8
        self.set_register(4, rsp)
        self.PC = return_address

    # ---------------- 栈操作指令 ----------------

    def pushq(self):
        """pushq: 压栈指令

        格式: A0 rA F
        功能: rsp -= 8; M[rsp] = rA
        """
        regA = self.get_front4bit(self.PC + 1)
        valA = self.get_register(regA)

        rsp = self.get_register(4)
        rsp -= 8
        self.write_8byte(rsp, valA)
        self.set_register(4, rsp)

        self.PC += 2

    def popq(self):
        """popq: 出栈指令

        格式: B0 rA F
        功能: rA = M[rsp]; rsp += 8
        """
        regA = self.get_front4bit(self.PC + 1)

        rsp = self.get_register(4)
        valM = self.get_8byte(rsp)
        rsp += 8
        self.set_register(4, rsp)
        self.set_register(regA, valM)

        self.PC += 2

    # ========================================================================
    # 第三部分: 模拟器执行引擎
    # ========================================================================

    def fetch(self):
        """取指令并执行 (Fetch-Decode-Execute)"""
        # 取指令
        head = self.memory.get(self.PC, None)

        # 检查是否访问了无效内存地址
        if head is None:
            self.status = 3  # 内存访问错误
            return

        # 解码: 提取操作码(高4位)
        opcode = (head >> 4) & 0xF

        # 执行: 根据操作码调用对应的指令处理函数
        if opcode in self.head_map:
            self.head_map[opcode]()
        else:
            self.status = 4  # 非法指令

    def run(self, program_input):
        """运行模拟器主循环

        Args:
            program_input: .yo 文件的内容字符串

        Returns:
            list: 所有状态历史记录
        """
        # 1. 解析输入文件
        instructions = self.parse_yo_file(program_input)

        if not instructions:
            # 如果没有有效指令，保存初始状态后返回
            self.save_states()
            return self.states

        # 2. 设置初始PC为第一条指令的地址
        self.PC = instructions[0]['address']

        # 3. 保存初始状态
        self.save_states()

        # 4. 执行循环
        while self.status == 1:  # 状态为 AOK 时继续执行
            # 检查步数限制(防止死循环)
            self.step_count += 1
            if self.step_count > self.max_steps:
                self.status = 4  # 超时视为非法指令
                self.save_states()
                break

            old_PC = self.PC

            # 取指执行
            self.fetch()

            # 如果发生错误,恢复PC到出错指令
            if self.status != 1:
                self.PC = old_PC

            # 保存执行后的状态
            self.save_states()

        return self.states

    # ========================================================================
    # 第四部分: 文件解析和状态管理
    # ========================================================================

    def parse_yo_file(self, content):
        """解析 .yo 格式的汇编文件

        .yo 文件格式示例:
            0x000:              | .pos 0
            0x000: 30f40008000000000000 | irmovq $8, %rsp

        Args:
            content: .yo 文件内容字符串

        Returns:
            list: 指令列表,每项包含地址和机器码
        """
        instructions = []

        for line in content.split('\n'):
            # 去除注释(以 | 分隔)
            code = line.split('|')[0].strip()

            # 跳过空行
            if code == "":
                continue

            # 检查是否包含冒号(地址:机器码格式)
            if ':' not in code:
                continue

            parts = code.split(':', 1)
            if len(parts) < 2:
                continue

            addr_str, machine_code_str = parts
            addr_str = addr_str.strip()
            machine_code_str = machine_code_str.strip()

            # 跳过只有标签没有机器码的行
            if machine_code_str == "":
                continue

            try:
                # 解析地址
                addr = int(addr_str, 16)

                # 解析机器码
                machine_code_str = machine_code_str.replace(' ', '')
                machine_bytes = bytes.fromhex(machine_code_str)

                # 加载到内存
                for i, byte in enumerate(machine_bytes):
                    self.memory[addr + i] = byte

                instructions.append({
                    "address": addr,
                    "machine_code": machine_code_str
                })
            except (ValueError, IndexError):
                # 忽略格式错误的行
                continue

        return instructions

    def save_states(self):
        """保存当前模拟器状态到历史记录

        状态包括: PC, 寄存器, 内存, 条件码, 状态码
        输出格式与标准答案保持一致
        """
        # 寄存器名称映射
        reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14"]
        registers_dict = {reg_names[i]: self.registers[i] for i in range(15)}

        # 检查状态是否与上一次相同(去重优化)
        current_state = {
            "PC": self.PC,
            "STAT": self.status,
            "ZF": self.ZF,
            "SF": self.SF,
            "OF": self.OF,
            "REG": tuple(self.registers)
        }

        if self.last_state == current_state:
            return

        self.last_state = current_state

        # 条件码
        CC = {
            "OF": self.OF,
            "SF": self.SF,
            "ZF": self.ZF
        }

        # 内存状态: 只记录非零的8字节块
        mem_state = {}
        memory_addresses = list(self.memory.keys())

        if memory_addresses:
            processed_blocks = set()

            for addr in memory_addresses:
                # 对齐到8字节边界
                block_addr = addr - (addr % 8)

                if block_addr in processed_blocks:
                    continue

                processed_blocks.add(block_addr)

                # 读取8字节值
                value = 0
                has_data = False

                for i in range(8):
                    byte_addr = block_addr + i
                    byte_val = self.memory.get(byte_addr, 0)
                    if byte_val != 0:
                        has_data = True
                    value |= (byte_val << (i * 8))

                if has_data:
                    # 转换为有符号表示
                    signed_value = self.to_signed(value)
                    signed_addr = self.to_signed(block_addr)
                    mem_state[str(signed_addr)] = signed_value

        # 寄存器状态(按字母顺序排序,转换为有符号)
        reg_state = {}
        for reg_name in sorted(registers_dict.keys()):
            reg_state[reg_name] = self.to_signed(registers_dict[reg_name])

        # 组装完整状态
        all_state = {
            "CC": CC,
            "MEM": mem_state,
            "PC": self.PC,
            "REG": reg_state,
            "STAT": self.status
        }

        self.states.append(all_state)


# ============================================================================
# 主程序入口
# ============================================================================

def main():
    """主函数: 从标准输入读取.yo文件,运行模拟器,输出JSON格式的状态历史"""

    # 读取标准输入的文件内容
    input_file = sys.stdin.read()

    # 创建模拟器实例
    CPU = Y86_Simulator()

    # 运行模拟器并获取状态历史
    states_history = CPU.run(input_file)

    # 去除初始状态(只保留指令执行后的状态)
    if states_history:
        states_history = states_history[1:]

    # 以JSON格式输出到标准输出
    json.dump(states_history, sys.stdout, indent=4)


if __name__ == "__main__":
    main()
