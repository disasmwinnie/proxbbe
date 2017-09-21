# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Helper module for access to x86(_64)  registers.
# Holds the state of the registers and returns the address range written
# when using +write_to+. .
# When given register is valid it returns the address range to the written
# register.
# x86_64 registers are constructed in the following hierarchy:
#       RAX           <---- all (first) 64bit
#        |
#       EAX           <---- last 32bit
#         |
#         AX          <---- last 16bit
#       |    |
#       AH   AL       <---- AL: last 8bit (8..64)
#                     <---- AH: second last 8bit (16..8)
module X86Reg_Utils
  # Gives a hash of all registers in different length (64,32,16,... bit) and
  # their subregisters. This effectively helps to know which subregisters of a
  # given (as key) registers
  # @return [Hash] with registers as key and Array with all their subregisters
  attr_reader :addr_reg
  @addr_reg = {
    # GENERAL PURPOSE REGISTER
    :rip => [:rip], # usually no access to that, but for consitancy's sake
    # Parts of rdi
    :rdi => [:rdi, :edi, :di, :dil],
    :edi => [:edi, :di, :dil],
    :di  => [:di, :dil],
    :dil  => [:dil],
    # Parts of rbp
    :rsi => [:rsi, :esi, :si, :sil],
    :esi => [:esi, :si, :sil],
    :si  => [:si, :sil],
    :sil  => [:sil],
    # Parts of rbp
    :rbp => [:rbp, :ebp, :bp, :bpl],
    :ebp => [:ebp, :bp, :bpl],
    :bp => [:bp, :bpl],
    :bpl => [:bpl],
    # Parts of rsp
    :rsp => [:rsp, :esp, :sp, :spl],
    :esp => [:esp, :sp, :spl],
    :sp => [:sp, :spl],
    :spl => [:spl],
    # Parts of rbx
    :rbx => [:rbx, :ebx, :bx, :bh, :bl],
    :ebx => [:ebx, :bx, :bh, :bl],
    :bx  => [:bx, :bh, :bl],
    :bh  => [:bh],
    :bl  => [:bl],
    # Parts of rdx
    :rdx => [:rdx, :edx, :dx, :dh, :dl],
    :edx => [:edx, :dx, :dh, :dl],
    :dx  => [:dx, :dh, :dl],
    :dh  => [:dh],
    :dl  => [:dl],
    # Parts of rcx
    :rcx => [:rcx, :ecx, :cx, :ch, :cl],
    :ecx => [:ecx, :cx, :ch, :cl],
    :cx  => [:cx, :ch, :cl],
    :ch  => [:ch],
    :cl  => [:cl],
    # Parts of rax
    :rax => [:rax, :eax, :ax, :ah, :al],
    :eax => [:eax, :ax, :ah, :al],
    :ax => [:ax, :ah, :al],
    :ah => [:ah],
    :al => [:al],

    :r8  => [:r8, :r8d, :r8w, :r8b],
    :r8d  => [:r8d, :r8w, :r8b],
    :r8w  => [:r8w, :r8b],
    :r8b  => [:r8b],

    :r9  => [:r9, :r9d, :r9w, :r9b],
    :r9d  => [:r9d, :r9w, :r9b],
    :r9w  => [:r9w, :r9b],
    :r9b  => [:r9b],

    :r10 => [:r10, :r10d, :r10w, :r10b],
    :r10d => [:r10d, :r10w, :r10b],
    :r10w => [:r10w, :r10b],
    :r10b => [:r10b],

    :r11 => [:r11, :r11d, :r11w, :r11b],
    :r11d => [:r11d, :r11w, :r11b],
    :r11w => [:r11w, :r11b],
    :r11b => [:r11b],

    :r12 => [:r12, :r12d, :r12w, :r12b],
    :r12d => [:r12d, :r12w, :r12b],
    :r12w => [:r12w, :r12b],
    :r12b => [:r12b],

    :r13 => [:r13, :r13d, :r13w, :r13b],
    :r13d => [:r13d, :r13w, :r13b],
    :r13w => [:r13w, :r13b],
    :r13b => [:r13b],

    :r14 => [:r14, :r14d, :r14w, :r14b],
    :r14d => [:r14d, :r14w, :r14b],
    :r14w => [:r14w, :r14b],
    :r14b => [:r14b],

    :r15 => [:r15, :r15d, :r15w, :r15b],
    :r15d => [:r15d, :r15w, :r15b],
    :r15w => [:r15w, :r15b],
    :r15b => [:r15b],
    # GENERAL PURPOSE REGISTER

    # SIMD,
    :zmm0 => [:zmm0, :ymm0, :xmm0],
    :ymm0 => [:ymm0, :xmm0],
    :xmm0 => [:xmm0],

    :zmm1 => [:zmm1, :ymm1, :xmm1],
    :ymm1 => [:ymm1, :xmm1],
    :xmm1 => [:xmm1],

    :zmm2 => [:zmm2, :ymm2, :xmm2],
    :ymm2 => [:ymm2, :xmm2],
    :xmm2 => [:xmm2],

    :zmm3 => [:zmm3, :ymm3, :xmm3],
    :ymm3 => [:ymm3, :xmm3],
    :xmm3 => [:xmm3],

    :zmm4 => [:zmm4, :ymm4, :xmm4],
    :ymm4 => [:ymm4, :xmm4],
    :xmm4 => [:xmm4],

    :zmm5 => [:zmm5, :ymm5, :xmm5],
    :ymm5 => [:ymm5, :xmm5],
    :xmm5 => [:xmm5],

    :zmm6 => [:zmm6, :ymm6, :xmm6],
    :ymm6 => [:ymm6, :xmm6],
    :xmm6 => [:xmm6],

    :zmm7 => [:zmm7, :ymm7, :xmm7],
    :ymm7 => [:ymm7, :xmm7],
    :xmm7 => [:xmm7],

    :zmm8 => [:zmm8, :ymm8, :xmm8],
    :ymm8 => [:ymm8, :xmm8],
    :xmm8 => [:xmm8],

    :zmm9 => [:zmm9, :ymm9, :xmm9],
    :ymm9 => [:ymm9, :xmm9],
    :xmm9 => [:xmm9],

    :zmm10 => [:zmm10, :ymm10, :xmm10],
    :ymm10 => [:ymm10, :xmm10],
    :xmm10 => [:xmm10],

    :zmm11 => [:zmm11, :ymm11, :xmm11],
    :ymm11 => [:ymm11, :xmm11],
    :xmm11 => [:xmm11],

    :zmm12 => [:zmm12, :ymm12, :xmm12],
    :ymm12 => [:ymm12, :xmm12],
    :xmm12 => [:xmm12],

    :zmm13 => [:zmm13, :ymm13, :xmm13],
    :ymm13 => [:ymm13, :xmm13],
    :xmm13 => [:xmm13],

    :zmm14 => [:zmm14, :ymm14, :xmm14],
    :ymm14 => [:ymm14, :xmm14],
    :xmm14 => [:xmm14],

    :zmm15 => [:zmm15, :ymm15, :xmm15],
    :ymm15 => [:ymm15, :xmm15],
    :xmm15 => [:xmm15],

    :zmm16 => [:zmm16],
    :zmm17 => [:zmm17],
    :zmm18 => [:zmm18],
    :zmm19 => [:zmm19],
    :zmm20 => [:zmm20],
    :zmm21 => [:zmm21],
    :zmm22 => [:zmm22],
    :zmm23 => [:zmm23],
    :zmm24 => [:zmm24],
    :zmm25 => [:zmm25],
    :zmm26 => [:zmm26],
    :zmm27 => [:zmm27],
    :zmm28 => [:zmm28],
    :zmm29 => [:zmm29],
    :zmm30 => [:zmm30],
    :zmm31 => [:zmm31]
    # SIMD
  }
end

# Helper module for register access used during inference. Main functions are
# giving the CPU value of a subregister (see #get_64_reg) and calculating the
# value of the given register (see #reg_value).
module Inference
  include X86Reg_Utils

  # Used during inference to get the name of the highest register from the
  # name of a particular subregister.
  # @param sub_reg [String] register used by operand
  # @return [Symbol] biggest register of given family, e.g., rax for eax
  def get_64_reg(sub_reg)
    X86Reg_Utils.addr_reg.each_pair do |reg,subregs|
      subregs.each do |subr|
        return reg.to_s if subr == sub_reg.to_sym
      end
    end
    throw "Invalid X86 register: #{sub_reg}"
  end

  # Used during inference to AND the values of registers
  @value_filter = {
    :first_512  => 2 ** 512 - 1,
    :first_256  => 2 ** 256 - 1,
    :first_128  => 2 ** 128 - 1,
    :first_64  => 2 ** 64 - 1,
    :first_32  => 2 ** 32 - 1,
    :first_16  => 2 ** 16 - 1,
    :last_8    => 65280,     # This is basically 1111_1111_0000_0000
    :first_8   => 2 ** 8 - 1
  }

  require 'set'
  @regs_512 = Set.new([:zmm0, :zmm1, :zmm2, :zmm3, :zmm4, :zmm5, :zmm6,
                       :zmm7, :zmm8, :zmm9, :zmm10, :zmm11, :zmm12, :zmm13,
                       :zmm14, :zmm15, :zmm16, :zmm17, :zmm18, :zmm19, :zmm20,
                       :zmm21, :zmm22, :zmm23, :zmm24, :zmm25, :zmm26, :zmm27,
                       :zmm28, :zmm29, :zmm30, :zmm31])
  @regs_256 = Set.new([:ymm0, :ymm1, :ymm2, :ymm3, :ymm4, :ymm5, :ymm6,
                       :ymm7, :ymm8, :ymm9, :ymm10, :ymm11, :ymm12, :ymm13,
                       :ymm14, :ymm15])
  @regs_128 = Set.new([:xmm0, :xmm1, :xmm2, :xmm3, :xmm4, :xmm5, :xmm6,
                       :xmm7, :xmm8, :xmm9, :xmm10, :xmm11, :xmm12, :xmm13,
                       :xmm14, :xmm15])
  @regs_64 = Set.new([:rip, :rdi, :rsi, :rbp, :rsp, :rbx, :rdx, :rcx, :rax,
                      :r8, :r9, :r10, :r11, :r12, :r13, :r14, :r15])
  @regs_32 = Set.new([:eip, :edi, :esi, :ebp, :esp, :ebx, :edx, :ecx, :eax,
                      :r8d, :r9d, :r10d, :r11d, :r12d, :r13d, :r14d, :r15d])
  @regs_16 = Set.new([:ip, :di, :si, :bp, :sp, :bx, :dx, :cx, :ax,
                      :r8w, :r9w, :r10w, :r11w, :r12w, :r13w, :r14w, :r15w])
  @regs_8 = Set.new([:dil, :sil, :bpl, :spl, :bl, :dl, :cl, :al,
                     :r8b, :r9b, :r10b, :r11b, :r12b, :r13b, :r14b, :r15b])
  @regs_8_last = Set.new([:ah, :bh, :ch, :dh])

  # Gives the right sub-value of the register. E.g. if you give a 64bit value,
  # but your register is eax, this methods gives you only the first 32bit, if
  # it's ax, only 16bit and so forth. This is needed since the trace contains
  # only values of the 64bit registers. Operands are sometimes sub-registers,
  # therefor it's essentail to calc these values.
  # @param reg_name [String] register used as operand
  # @param value [Integer] value of CPU register, which subvalue is looked for
  def reg_value(reg_name, value)
    reg_name = reg_name.to_sym
    if @regs_512.include?(reg_name)
      return value & @value_filter[:first_512]
    elsif @regs_256.include?(reg_name)
      return value & @value_filter[:first_256]
    elsif @regs_128.include?(reg_name)
      return value & @value_filter[:first_128]
    elsif @regs_64.include?(reg_name)
      return value & @value_filter[:first_64]
    elsif @regs_32.include?(reg_name)
      return value & @value_filter[:first_32]
    elsif @regs_16.include?(reg_name)
      return value & @value_filter[:first_16]
    elsif @regs_8.include?(reg_name)
      return value & @value_filter[:first_8]
    elsif @regs_8_last.include?(reg_name)
      return value & @value_filter[:last_8]
    else
      throw "Invalid x86 register: #{reg_name}"
    end
  end
end


# Helper module used during tainting phase. Returns array of all
# sub-registers involved when a tainted write is happening to a certain
# register.
module Tainting
  include X86Reg_Utils
  # Gives an array of all sub-registers of a given register name. This is
  # needed to keep all tainted registers after a write. E.g., if rax shall be
  # tainted it also has sub-registers to be tainted with it: eax, ax, ah, al.
  # @param reg [String] register used as an operand during tainted write
  # @return [Array] of sub-registers to be tainted
  def write_to(reg)
    reg = reg.to_sym
    # Returns array of registers to taint
    address_and_reg = X86Reg_Utils.addr_reg[reg]
    if address_and_reg
      return address_and_reg
    else
      raise 'Invalid register. Sure it is a x86_64 trace?'
    end
  end

  # Returns all parts a register consists of. If you give the method 'ecx', for
  # example, it will return a list with [:ecx, cx, cl, ch]
  # @param reg [Symbol] register name
  # @return [Array] all sub-registers as symbols, including the method param
  def all_reg_parts(reg)
    return X86Reg_Utils.addr_reg[reg]
  end
end
