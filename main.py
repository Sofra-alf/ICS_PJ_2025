class Y86_Simolator:
    def __init__(self):
        self.PC = 0
        self.registers = [0] * 15
        #寄存器由数字保存，将对应的寄存器存到对应索引中
        self.memory = {}
        self.ZF = 0
        self.SF = 0
        self.OF = 0

        self.status = 1 #1: AOK, 2: HLT, 3: ADR, 4: INS


    def get_byte(self, address):
        return self.memory.get(address, 0) & 0xFF #异常输出0

    def get_front4bit(self, address):
        byte = self.get_byte(address)
        return (byte >> 4) & 0xF
    
    def get_back4bit(self, address):
        byte = self.get_byte(address)
        return byte & 0xF

    #读取地址后8byte的数据
    def get_8byte(self, address):
        result = 0
        for i in range(8):
            byte = self.get_byte(address + i)
            result |= (byte << (i * 8))
        return result
    
    def write_8byte(self, address, value):
        for i in range(8):
            byte = (value >> (i * 8)) & 0xFF
            self.memory[address + i] = byte
        return
    
    def halt(self):
        self.status = 2
        self.PC += 1
        return
    
    def nop(self):
        self.PC += 1
        return
    
    def rrmove_comv(self):
        func = self.get_back4bit(self.PC)
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)

        con = False
        if func == 0x0: #rrmovq
            con = True
        elif func == 0x1: #cmovle
            con = (self.SF ^ self.OF) | self.ZF
        elif func == 0x2: #cmovl
            con = self.SF ^ self.OF
        elif func == 0x3: #cmove
            con = self.ZF
        elif func == 0x4: #cmovne
            con = not self.ZF
        elif func == 0x5: #cmovge
            con = not (self.SF ^ self.OF)
        elif func == 0x6: #cmovg
            con = not (self.SF ^ self.OF) and not self.ZF
        else:
            self.status = 4
            self.PC += 2
            return
        
        if con:
            self.registers[regB] = self.registers[regA]
        
        self.PC += 2
        return
    
    def irmovq(self):
        regB = self.get_back4bit(self.PC + 1)
        value = self.get_8byte(self.PC + 2)

        self.registers[regB] = value

        self.PC += 10
        return
    
    def rmmovq(self):
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)
        displacement = self.get_8byte(self.PC + 2)

        address = self.registers[regB] + displacement
        value = self.registers[regA]
        self.write_8byte(address, value)

        self.PC += 10
        return
    
    def mrmovq(self):
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)
        displacement = self.get_8byte(self.PC + 2)

        address = self.registers[regB] + displacement
        if address == 0:
            self.status = 3
            self.PC += 10
            return
        
        value = self.get_8byte(address)
        self.registers[regA] = value

        self.PC += 10
        return
    
    def OPq(self):
        func = self.get_back4bit(self.PC)
        regA = self.get_front4bit(self.PC + 1)
        regB = self.get_back4bit(self.PC + 1)

        valA = self.registers[regA]
        valB = self.registers[regB]
        result = 0

        if func == 0x0: #addq
            result = valB + valA
        elif func == 0x1: #subq
            result = valB - valA
        elif func == 0x2: #andq
            result = valB & valA
        elif func == 0x3: #xorq
            result = valB ^ valA
        else:
            self.status = 4
            self.PC += 2
            return
        
        self.registers[regB] = result

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

        con = False
        if func == 0x0: #jmp
            con = True
        elif func == 0x1: #jle
            con = (self.SF ^ self.OF) | self.ZF
        elif func == 0x2: #jl
            con = self.SF ^ self.OF
        elif func == 0x3: #je
            con = self.ZF
        elif func == 0x4: #jne
            con = not self.ZF
        elif func == 0x5: #jge
            con = not (self.SF ^ self.OF)
        elif func == 0x6: #jg
            con = not (self.SF ^ self.OF) and not self.ZF
        else:
            self.status = 4
            self.PC += 9
            return
        
        if con:
            self.PC = destination #可能非法地址
            if self.memory.get(self.PC, 0) == 0:
                self.status = 3
        else:
            self.PC += 9
        return
    
    def call(self):
        destination = self.get_8byte(self.PC + 1)

        rsp = self.registers[4] #rsp ~ 0x4
        rsp -= 8
        self.write_8byte(rsp, self.PC + 9)
        self.registers[4] = rsp

        self.PC = destination
        return
    
    def ret(self):
        rsp = self.registers[4]
        return_address = self.get_8byte(rsp)
        rsp += 8
        self.registers[4] = rsp

        self.PC = return_address
        return
    
    def pushq(self):
        regA = self.get_front4bit(self.PC + 1)
        valA = self.registers[regA]
        
        rsp = self.registers[4] #rsp ~ 0x4
        rsp -= 8
        self.write_8byte(rsp, valA)
        self.registers[4] = rsp

        self.PC += 2
        return
    
    def popq(self):
        regA = self.get_front4bit(self.PC + 1)

        rsp = self.registers[4]
        valM = self.get_8byte(rsp)
        self.registers[regA] = valM
        rsp += 8
        self.registers[4] = rsp

        self.PC += 2
        return
    






