import sys
import json
class Y86_Simulator:
    def __init__(self):
        self.PC = 0
        self.registers = [0] * 15
        #寄存器由数字保存，将对应的寄存器存到对应索引中
        self.memory = {}
        self.ZF = 1
        self.SF = 0
        self.OF = 0

        self.status = 1 #1: AOK, 2: HLT, 3: ADR, 4: INS

        # 状态历史记录
        self.states = []
        self.last_state = None
        self.step_count = 0
        self.max_steps = 10000  # 默认最大步数

        # 指令操作码映射表
        self.head_map = {
            0x0: self.halt,      # halt
            0x1: self.nop,       # nop
            0x2: self.rrmove_comv,  # rrmovq/cmovXX
            0x3: self.irmovq,    # irmovq
            0x4: self.rmmovq,    # rmmovq
            0x5: self.mrmovq,    # mrmovq
            0x6: self.OPq,       # OPq (addq, subq, andq, xorq)
            0x7: self.jump,      # jXX (jmp, jle, jl, je, jne, jge, jg)
            0x8: self.call,      # call
            0x9: self.ret,       # ret
            0xA: self.pushq,     # pushq
            0xB: self.popq       # popq
        }

    def get_memory(self, address):
        if address < 0:
            return
        data = self.memory.get(address, 0)
        return data


    def get_byte(self, address):
        return self.get_memory(address) & 0xFF #异常输出0

    def get_front4bit(self, address):
        byte = self.get_byte(address)
        return (byte >> 4) & 0xF

    def get_back4bit(self, address):
        byte = self.get_byte(address)
        return byte & 0xF

    def get_register(self, reg_num):
        """安全地获取寄存器值"""
        if reg_num > 15:
            self.status = 4  # 非法寄存器编号 -> 非法指令
            return 0
        if reg_num == 15:  # 0xF 表示无寄存器
            return 0
        return self.registers[reg_num]

    def set_register(self, reg_num, value):
        """安全地设置寄存器值"""
        if reg_num > 15:
            self.status = 4  # 非法寄存器编号 -> 非法指令
            return
        if reg_num < 15:  # 0xF 表示无寄存器,不设置
            # 确保值在64位范围内
            self.registers[reg_num] = value & 0xFFFFFFFFFFFFFFFF
        return


    #读取地址后8byte的数据
    def get_8byte(self, address):
        result = 0
        for i in range(8):
            byte = self.get_byte(address + i)
            result |= (byte << (i * 8))
        return result
    
    def write_8byte(self, address, value):
        """写入8字节到内存,负地址会设置错误状态"""
        if address < 0:
            self.status = 3  # 地址错误
            return False
        for i in range(8):
            byte = (value >> (i * 8)) & 0xFF
            self.memory[address + i] = byte
        return True

    def to_signed(self, value):
        """将64位无符号数转换为有符号数"""
        if value >= (1 << 63):  # 如果最高位是1
            return value - (1 << 64)
        return value

    def check_condition(self, func_code):
        """根据功能码检查条件码,返回条件是否满足

        Args:
            func_code: 条件码 (0x0-0x6)

        Returns:
            True/False: 条件是否满足
            None: 非法的功能码
        """
        if func_code == 0x0:  # 无条件 (rrmovq/jmp)
            return True
        elif func_code == 0x1:  # le (<=)
            return (self.SF ^ self.OF) | self.ZF
        elif func_code == 0x2:  # l (<)
            return self.SF ^ self.OF
        elif func_code == 0x3:  # e (==)
            return self.ZF
        elif func_code == 0x4:  # ne (!=)
            return not self.ZF
        elif func_code == 0x5:  # ge (>=)
            return not (self.SF ^ self.OF)
        elif func_code == 0x6:  # g (>)
            return not (self.SF ^ self.OF) and not self.ZF
        else:
            return None  # 非法功能码
    
    def add(self, a, b):
        return (a + b) & 0xFFFFFFFFFFFFFFFF
    
    def sub(self, a, b):
        return (a - b) & 0xFFFFFFFFFFFFFFFF
    
    def halt(self):
        self.status = 2
        return
    
    def nop(self):
        self.PC += 1
        return
    
    def rrmove_comv(self):
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
        return
    
    def irmovq(self):
        regB = self.get_back4bit(self.PC + 1)
        value = self.get_8byte(self.PC + 2)

        self.set_register(regB, value)

        self.PC += 10
        return
    
    def rmmovq(self):
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)
        displacement = self.get_8byte(self.PC + 2)

        address = self.add(self.get_register(regB), displacement)
        value = self.get_register(regA)
        self.write_8byte(address, value)

        self.PC += 10
        return
    
    def mrmovq(self):
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)
        displacement = self.get_8byte(self.PC + 2)

        address = self.add(self.get_register(regB), displacement)
        if address == 0:
            self.status = 3
            self.PC += 10
            return

        value = self.get_8byte(address)
        self.set_register(regA, value)

        self.PC += 10
        return
    
    def OPq(self):
        func = self.get_back4bit(self.PC)
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)

        valA = self.get_register(regA)
        valB = self.get_register(regB)
        result = 0

        if func == 0x0: #addq
            result = self.add(valB, valA)
        elif func == 0x1: #subq
            result = self.sub(valB, valA)
        elif func == 0x2: #andq
            result = valB & valA
        elif func == 0x3: #xorq
            result = valB ^ valA
        else:
            self.status = 4
            self.PC += 2
            return

        self.set_register(regB, result)

        self.ZF = 1 if result == 0 else 0
        self.SF = 1 if (result >> 63) & 0x1 else 0


        signA = (valA >> 63) & 0x1
        signB = (valB >> 63) & 0x1
        signR = (result >> 63) & 0x1

        if func == 0x0: #addq溢出判断
            self.OF = 1 if (signA == signB and signA != signR) else 0
        elif func == 0x1: #subq溢出判断
            self.OF = 1 if (signA != signB and signB != signR) else 0
        else:
            self.OF = 0

        self.PC += 2
        return
    
    def jump(self):
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
        return
    
    def call(self):
        destination = self.get_8byte(self.PC + 1)

        rsp = self.get_register(4) #rsp ~ 0x4
        rsp -= 8
        self.write_8byte(rsp, self.PC + 9)
        self.set_register(4, rsp)

        self.PC = destination
        return
    
    def ret(self):
        rsp = self.get_register(4)
        return_address = self.get_8byte(rsp)
        rsp += 8
        self.set_register(4, rsp)

        self.PC = return_address
        return
    
    def pushq(self):
        regA = self.get_front4bit(self.PC + 1)
        valA = self.get_register(regA)

        rsp = self.get_register(4) #rsp ~ 0x4
        rsp -= 8
        self.write_8byte(rsp, valA)
        self.set_register(4, rsp)

        self.PC += 2
        return
    
    def popq(self):
        regA = self.get_front4bit(self.PC + 1)

        rsp = self.get_register(4)
        valM = self.get_8byte(rsp)
        rsp += 8
        self.set_register(4, rsp)
        self.set_register(regA, valM)
        

        self.PC += 2
        return
    

    def parse_yo_file(self,content):
        instructions = []

        for line in content.split('\n'):
            #去除注释
            code = line.split('|')[0].strip()

            #针对文件中可能不出现代码只有注释的行，直接跳过
            if code == "":
                continue

            # 检查是否是标签行（只有地址没有机器码）
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
                addr = int(addr_str, 16)
                # 移除机器码中的空格
                machine_code_str = machine_code_str.replace(' ', '')
                machine_bytes = bytes.fromhex(machine_code_str)
                for i, byte in enumerate(machine_bytes):
                    self.memory[addr + i] = byte

                instructions.append({
                    "address": addr,
                    "machine_code": machine_code_str
                })
            except (ValueError, IndexError):
                continue

        return instructions

    def save_states(self):
        """保存当前模拟器状态到历史记录"""
        # 创建寄存器字典（适配列表格式）
        reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14"]
        registers_dict = {reg_names[i]: self.registers[i] for i in range(15)}

        # 检查状态是否与上一次相同，避免保存重复状态
        current_state = {
            "PC": self.PC,
            "STAT": self.status,
            "ZF": self.ZF,
            "SF": self.SF,
            "OF": self.OF,
            "REG": tuple(self.registers)
        }

        # 简单比较，如果状态相同则跳过保存
        if self.last_state == current_state:
            return

        self.last_state = current_state

        # 条件码
        CC = {
            "OF": self.OF,
            "SF": self.SF,
            "ZF": self.ZF
        }

        # 优化内存状态保存：只记录非零内存块
        mem_state = {}

        # 获取所有已使用的内存地址
        memory_addresses = list(self.memory.keys())
        if memory_addresses:
            # 使用集合来记录已处理的块，避免重复处理
            processed_blocks = set()

            for addr in memory_addresses:
                block_addr = addr - (addr % 8)  # 对齐到8字节边界

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
                    # 将内存地址也转换为有符号表示
                    signed_addr = self.to_signed(block_addr)
                    mem_state[str(signed_addr)] = signed_value

        # 寄存器状态（按字母顺序排序并转换为有符号）
        reg_state = {}
        for reg_name in sorted(registers_dict.keys()):
            reg_state[reg_name] = self.to_signed(registers_dict[reg_name])

        # 本次指令结束后所有部分的状态
        all_state = {
            "CC": CC,
            "MEM": mem_state,
            "PC": self.PC,
            "REG": reg_state,
            "STAT": self.status
        }
        self.states.append(all_state)

    def fetch(self):
        """取指令并执行"""
        head = self.memory.get(self.PC, None)

        # 检查是否访问了无效内存地址
        if head is None:
            self.status = 3  # 内存访问错误
            return

        # 提取操作码(高4位)
        opcode = (head >> 4) & 0xF

        # 根据操作码调用对应的指令处理函数
        if opcode in self.head_map:
            self.head_map[opcode]()
        else:
            self.status = 4  # 非法指令

    def run(self, program_input):
        """运行模拟器

        Args:
            program_input: .yo 文件的内容字符串

        Returns:
            states: 所有状态历史列表
        """
        # 读取并解析文件
        instructions = self.parse_yo_file(program_input)

        if not instructions:
            # 如果没有有效指令，保存初始状态后返回
            self.save_states()
            return self.states

        # 设置初始PC为第一条指令的地址
        if instructions:
            self.PC = instructions[0]['address']

        # 保存初始状态
        self.save_states()

        # 执行循环
        while self.status == 1:  # 正常执行
            # 检查步数限制
            self.step_count += 1
            if self.step_count > self.max_steps:
                self.status = 4  # 超时状态
                self.save_states()
                break

            old_PC = self.PC
            # 解码并执行指令
            self.fetch()

            # 检查是否应该停止
            if self.status != 1:
                self.PC = old_PC

            # 保存执行后状态（每条指令执行后保存）
            self.save_states()

            

        return self.states


def main():
    """主函数：从标准输入读取.yo文件内容，运行模拟器，输出JSON格式的状态历史"""

    # 读取标准输入的文件内容
    input_file = sys.stdin.read()

    # 创建模拟器实例
    CPU = Y86_Simulator()

    # 运行模拟器并获取状态历史
    states_history = CPU.run(input_file)
    if states_history:
        states_history = states_history[1:]

    # 以JSON格式输出到标准输出
    json.dump(states_history, sys.stdout, indent=4)


# 使用示例
if __name__ == "__main__":
    main()


