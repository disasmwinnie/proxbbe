# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Module containing mapping of instruction class used by PIN framework.
require 'set'
module Iclass
  # Instruction mapping
  I = {
    # === arithmetic
    adc: 5,
    adc_lock: 7,
    add: 8,
    add_lock: 15,
    and: 23,
    and_lock: 29,
    or: 466,
    or_lock: 469,
    xor: 1508, # null if reg1==reg2
    xor_lock: 1511, # null if reg1==reg2
    sbb: 713, # null if reg1==reg2
    sbb_lock: 714, # null if reg1==reg2
    sub: 773, # null if reg1==reg2
    sub_lock: 778, # null if reg1==reg2
    # Shifts, most of the follow $INSTR $dst_reg, imm, but sometimes there's
    # an register as src (always al). This can be handled as arithmetic
    # instructions in a generic way.
    rcl:		 646,
    rcr:		 649,
    rol:		 697,
    ror:		 698,
    rorx:		 699,
    sar:		 710,
    sarx:		 711,
    shl:		 745,
    shld:		 746,
    shlx:		 747,
    shr:		 748,
    shrd:		 749,
    shrx:		 750,
    # === arithmetic
    # === conditional XFER
    cmovb:   83,    # cf==1
    cmovbe:  84,    # cf==1 || zf==1
    cmovl:   85,    # sf!=of
    cmovle:  86,    # sf!=of || zf==1
    cmovnb:  87,    # cf==0
    cmovnbe: 88,    # cf==0 && zf==0
    cmovnl:  89,    # sf==of
    cmovnle: 90,    # zf==0 && sf==of
    cmovno:  91,    # of==0
    cmovnp:  92,    # pf==0
    cmovns:  93,    # sf==0
    cmovnz:  94,    # zf==0
    cmovo:   95,    # of==1
    cmovp:   96,    # pf==1
    cmovs:   97,    # sf==1
    cmovz:   98,    # zf==1
    # === conditional XFER
    # === unconditional XFER
    bsf:      55,
    bsr:      56,
    mov:      403,
    xlat:     1507,
    # Moves only 1 or 2 byte to 16/32/64 register. Since PIN always offers the
    # length of the destination, we don't need to do case differentiation.
    # E.g., mov edi, al, will have al as source and edi as destination.
    # Therefore, we spread the the taint from al to edi like for normal mov.
    # We ignore whether it was sign or zero extend, since the resulting value
    # is always results from the source one way or antoher.
    movsx:    438,
    movsxd:   439,
    movzx:    442,
    # Same as mov.
    pop:      585,
    push:     639,
    # from rip to mw, rip always untainted, so handle like XFER wen mw tainted.
    far_call:   66,
    near_call:  67,
    # === unconditional XFER
    # === Exchange/Extend regs
    cbw:      68,  # AL    -> AX
    cwd:      141,  # AX    -> DX
    cwde:     142,  # AX    -> EAX
    cdq:      69,  # EAX   -> EDX
    cdqe:     70,  # EAX   -> RAX
    cqo:      117,  # RAX   -> RDX
    # === Exchange/Extend regs
    # === EXTRAWURST - custom decision for each instruction
    rdtsc:    659,     # clear dst eax, edx
    rdtscp:   660,     # clear dst eax, edx, ex
    rdmsr:    652,     # clear dst rax, rdx
    rdpmc:    654,     # clear dst eax, edx
    cpuid:    116,     # clear dst eax, edx, ebx, ecx
    xchg:     1504,    # xchg
    leave:    368,     # destroy stack frame: move esp, ebp then pop ebp
    enter:    159,     # create stackframe push ebp, then mov ebp, esp
    lea:      367,
    # xchg and add: can be handled as point arithmetic, except when a memory is
    # involved.
    xadd:     1501,
    xadd_lock:     1502,
    # === EXTRAWURST - custom decision for each instruction
    # === point arithmetic
    div:      147,
    idiv:     265,
    mul:      446,
    mulx:     451,
    imul:     266,
    # === point arithmetic
    # === Unconditional set/clear
    stmxcsr:  767, # untag dst register
    lar:      363, # untag dst register
    smsw:     757, # untag dst register or memory
    str:      772, # untag dst register or memory
    lahf:     362, # clear AH
    salc:     709, # sets al to value of carry flag, always overwrites.
    # === Unconditional set/clear
    # === Conditional set/clear
    setb:     719,    # cf==1
    setbe:    720,    # cf==1 || zf==1
    setl:     721,    # sf!=of
    setle:    722,    # sf!=of || zf==1
    setnb:    723,    # cf==0
    setnbe:   724,    # cf==0 && zf==0
    setnl:    725,    # sf==of
    setnle:   726,    # zf==0 && sf==of
    setno:    727,    # of==0
    setnp:    728,    # pf==0
    setns:    729,    # sf==0
    setnz:    730,    # zf==0
    seto:     731,    # of==1
    setp:     732,    # pf==1
    sets:     733,    # sf==1
    setz:     735,    # zf==1
    # === Conditional set/clear
    # === REP prefix, counter needs to be cleaned. Then handle like XFER.
    ret_lodsb:    680,
    ret_lodsd:    681,
    ret_lodsq:    682,
    ret_lodsw:    683,
    ret_stosb:    691,
    ret_stosd:    692,
    ret_stosq:    693,
    ret_stosw:    694,
    ret_movsb:    684,
    ret_movsd:    685,
    ret_movsq:    686,
    ret_movsw:    687,
    lodsb:        378,
    lodsd:        379,
    lodsq:        380,
    lodsw:        381,
    stosb:        768,
    stosd:        769,
    stosq:        770,
    stosw:        771,
    movsb:        430,
    movsd:        431,
    movsq:        435,
    movsw:        437,
    # === REP prefix, counter needs to be cleaned. Then handle like XFER.
    cmp: 99,
    # Handle like cmp, since ZF is set. Taint-spreading not implemented.
    cmpxchg:          108,
    cmpxchg_lock:     113,
    cmpxchg8b:        111,
    cmpxchg8b_lock:   112,
    # String compares
    cmpsb:            102,
    cmpsd:            103,
    cmpsq:            105,
    cmpsw:            107,
    repe_cmpsb:       661,
    repe_cmpsd:       662,
    repe_cmpsq:       663,
    repe_cmpsw:       664,
    repne_cmpsb:      669,
    repne_cmpsd:      670,
    repne_cmpsq:      671,
    repne_cmpsw:      672,
    # String compares

    # test, used for zero compare, not for taint spreading.
    test:             787,
    # test, used for zero compare, not for taint spreading.

    # === Not implemented
    # Handle like cmp, since ZF is set. Taint-spreading skipped.
    #cmpxchg: 106,
    #cmpxchg_lock:     111,
    #cmpxchg8b:        109,
    #cmpxchg8b_lock:   110,
    #enter arg1, arg2 # enter _without_ arguments is implemented
    # === Not implemented
    # ===JMPs
    jb:               290,
    jbe:              291,
    jcxz:             292,
    jecxz:            293,
    jl:               294,
    jle:              295,
    jmp:              296, # unconditional
    jmp_far:          297, # unconditional
    jnb:              298,
    jnbe:             299,
    jnl:              300,
    jnle:             301,
    jno:              302,
    jnp:              303,
    jns:              304,
    jnz:              305,
    jo:               306,
    jp:               307,
    jrcxz:            308,
    js:               309,
    jz:               310,
    # ===JMPs
  }

  # Used during inference phase to determine necessary mnemonics.
  module Inference
    # Check if given mnemonic is a conditional jump.
    # @param iclass [Integer] PIN's representation of opcode
    # @return [Boolean] true if conditional jump mnemonic, otherwise nil
    def cond_jmp?(iclass)
      if iclass == I[:jb] ||
          iclass == I[:jbe] ||
          iclass == I[:jcxz] ||
          iclass == I[:jecxz] ||
          iclass == I[:jl] ||
          iclass == I[:jle] ||
          iclass == I[:jnb] ||
          iclass == I[:jnbe] ||
          iclass == I[:jnl] ||
          iclass == I[:jnle] ||
          iclass == I[:jno] ||
          iclass == I[:jnp] ||
          iclass == I[:jns] ||
          iclass == I[:jnz] ||
          iclass == I[:jo] ||
          iclass == I[:jp] ||
          iclass == I[:jrcxz] ||
          iclass == I[:js] ||
          iclass == I[:jz]
        return true
      end
    end

    # Check if given mnemonic is an un-conditional jump.
    # @param iclass [Integer] PIN's representation of opcode
    # @return [Boolean] true if un-conditional jump mnemonic, otherwise nil
    def uncond_jmp?(iclass)
      if iclass == I[:jmp] || iclass == I[:jmp_far]
        return true
      end
    end

    # Check if given mnemonic is used to compare two values.
    # @param iclass [Integer] PIN's representation of opcode
    # @return [Boolean] true if cmp mnemonic, otherwise nil
    def compare?(iclass)
      if iclass == I[:cmp] || iclass == I[:cmpxchg] ||
          iclass == I[:cmpxchg_lock] || iclass == I[:cmpxchg8b] ||
          iclass == I[:cmpxchg8b_lock] || iclass == I[:sub_lock] ||
          iclass == I[:sub] || iclass == I[:cmpsb] || iclass == I[:cmpsd] ||
          iclass == I[:cmpsq] || iclass == I[:cmpsw] ||
          # repe_cmpsX and repne_cmpsX
          iclass == I[:repe_cmpsb] || iclass == I[:repe_cmpsb] ||
          iclass == I[:repe_cmpse] || iclass == I[:repe_cmpsw] ||
          iclass == I[:repne_cmpsb] || iclass == I[:repne_cmpsd] ||
          iclass == I[:repne_cmpsq] || iclass == I[:repne_cmpsw]
        return true
      end
    end

    # Check if given mnemonic is a compare and xchange.
    # This is needed to clean up parameters during delimiter inference.
    # @param iclass [Integer] PIN's representation of opcode
    # @return [Boolean] true if cmpXCHG mnemonic, otherwise nil
    def xchg_compare?(iclass)
      if iclass == I[:cmpxchg_lock] || iclass == I[:cmpxchg8b] ||
          iclass == I[:cmpxchg8b_lock] || iclass == I[:cmpxchg]
        return true
      end
    end

    # Checks if a given mnemonic is used to check a register for the value zero.
    # @param iclass [Integer] PIN's representation of opcode
    # @return [Boolean] true if compares for zero, otherwise nil
    def zero_compare?(iclass)
      if iclass == I[:test] || iclass == I[:or] ||  iclass == I[:or_lock] ||
          iclass == I[:and] ||  iclass == I[:and_lock]
        return true
      end
    end
  end

  # Enum to check if particular flags in the (E)FLAG register are set. Used
  # as helper for conditional instructions like cmovns.
  module FlagEval
    CF = 0b1
    PF = 0b100
    AF = 0b10_000
    ZF = 0b1_000_000
    SF = 0b10_000_000
    TF = 0b100_000_000
    IF = 0b1_000_000_000
    DF = 0b10_000_000_000
    OF = 0b100_000_000_000

    def carry_set?(flags)
      CF == (CF & flags) ? true : false
    end

    def parity_set?(flags)
      PF == (PF & flags) ? true : false
    end

    def adjust_set?(flags)
      AF == (AF & flags) ? true : false
    end

    def zero_set?(flags)
      ZF == (ZF & flags) ? true : false
    end

    def sign_set?(flags)
      SF == (SF & flags) ? true : false
    end

    def overflow_set?(flags)
      OF == (OF & flags) ? true : false
    end
  end

  module Tainting
    # Enum to set a particular action for the tainting engine.
    module TaintAction
      NOTHING = 0
      XFER = 1
      UNION = 2
      CLEAR_REG = 3
      CLEAR_MULT_REG = 4
      POINTER_ARITHMETIC = 5
      XCHG = 6
      REP_PREFIX = 7
      ENTER = 8
      LEAVE = 9
      LEA = 10
    end

    include FlagEval

    def multiple_rw?(t_action)
      if t_action == TaintAction::POINTER_ARITHMETIC ||
          t_action == TaintAction::CLEAR_MULT_REG ||
          t_action == TaintAction::XCHG ||
          t_action == TaintAction::ENTER || t_action == TaintAction::LEAVE
        return true
      end
    end

    def multiple_mr?(iclass)
      if iclass == I[:cmpsb] || iclass == I[:cmpsd] ||
          iclass == I[:cmpsq] || iclass == I[:cmpsw] ||
          # repe_cmpsX and repne_cmpsX
          iclass == I[:repe_cmpsb] || iclass == I[:repe_cmpsb] ||
          iclass == I[:repe_cmpse] || iclass == I[:repe_cmpsw] ||
          iclass == I[:repne_cmpsb] || iclass == I[:repne_cmpsd] ||
          iclass == I[:repne_cmpsq] || iclass == I[:repne_cmpsw]
        return true
    end


    end

    def analyze_iclass(iclass, flags)
      if xfer?(iclass)
        return TaintAction::XFER
      elsif cond_xfer?(iclass)
        if condition_statisfied?(iclass, flags)
          return TaintAction::XFER
        else
          return TaintAction::NOTHING
        end
      elsif iclass == I[:lea]
        return TaintAction::LEA
      elsif arithmetic?(iclass)
        return TaintAction::UNION
      elsif pointer_arithmetic?(iclass)
        return TaintAction::POINTER_ARITHMETIC
      elsif iclass == I[:leave]
        return TaintAction::LEAVE
      elsif iclass == I[:enter]
        return TaintAction::ENTER
      elsif rep_prefix?(iclass)
        return TaintAction::REP_PREFIX
      elsif iclass == I[:stmxcsr] || iclass == I[:lar] || iclass == I[:smsw] ||
        iclass == I[:str] || iclass == I[:lahf] || iclass == I[:salc]
        # Unconditioned set, respectively unset of label
        return TaintAction::CLEAR_REG
      elsif iclass == I[:setb] || iclass == I[:setbe] || iclass == I[:setl] ||
        iclass == I[:setle] || iclass == I[:setnb] || iclass == I[:setnbe]
        iclass == I[:setnl] || iclass == I[:setnle] || iclass == I[:setno]
        iclass == I[:setnp] || iclass == I[:setns] || iclass == I[:setnz]
        iclass == I[:seto] || iclass == I[:setp]
        # Conditioned set, respectively unset of label
        if condition_statisfied?(iclass, flags)
          return TaintAction::CLEAR_REG
        else
          return TaintAction::NOTHING
        end
      elsif iclass == I[:rdtsc] || iclass == I[:rdtscp] || iclass == I[:rdmsr] ||
        iclass == I[:rdpmc] || iclass == [:cpuid]
        return TaintAction::CLEAR_MULT_REG
      elsif iclass == I[:xchg]
        return TaintAction::XCHG
      else
        # Unhandled instruction: unknown or not needed for taint-spreading.
        return TaintAction::NOTHING
      end
    end

    def condition_statisfied?(iclass, flags)
      case iclass
      when I[:setb], I[:cmovb] # setb, cmovb
        return FlagEval::carry_set?(flags)
      when I[:setbe], I[:cmovbe] # setbe, cmovbe
        return FlagEval::carry_set?(flags) || FlagEval::zero_set?(flags)
      when I[:setl], I[:cmovl] # setl, cmovl
        # only one can be true
        return FlagEval::sign_set?(flags) ^ FlagEval::overflow_set?(flags)
      when I[:setle], I[:cmovle] # setle, cmovle
        return FlagEval::zero_set?(flags) ||
          (FlagEval::sign_set?(flags) ^ FlagEval::overflow_set?(flags))
      when I[:setnb], I[:cmovnb] # setnb, cmovnb
        return FlagEval::carry_set?(flags)
      when I[:setnbe], I[:cmovnbe] # setnbe, cmovnbe
        # both must be not set
        return !FlagEval::carry_set?(flags) && !FlagEval::zero_set?(flags)
      when I[:setnl], I[:cmovnl] # setnl, cmovnl
        # both must be equal
        return FlagEval::sign_set?(flags) == FlagEval::overflow_set?(flags)
      when I[:setnle], I[:cmovnle] # setnle, cmovnle
        return FlagEval::zero_set?(flags) &&
          (FlagEval::sign_set?(flags) == FlagEval::overflow_set?(flags))
      when I[:setno], I[:cmovno] # setno, cmovno
        return !FlagEval::overflow_set?(flags)
      when I[:setnp], I[:cmovnp] # setnp, cmovnp
        return !FlagEval::parity_set?(flags)
      when I[:setns], I[:cmovns] # setns, cmovns
        return !FlagEval::sign_set?(flags)
      when I[:setnz], I[:cmovnz] # setnz, cmovnz
        return !FlagEval::zero_set?(flags)
      when I[:seto], I[:cmovo] # seto, cmovo
        return FlagEval::overflow_set?(flags)
      when I[:setp], I[:cmovp] # setp, cmovp
        return FlagEval::parity_set?(flags)
      when I[:sets], I[:cmovs] # sets, cmovs
        return FlagEval::sign_set?(flags)
      when I[:setz], I[:cmovz] # setz, cmovz
        return FlagEval::zero_set?(flags)
      else
        raise "Unsupported/unimplemented iclass #{iclass}"
      end
    end

    def xfer?(iclass)
      if iclass == I[:mov]  || iclass == I[:push] || iclass == I[:pop] ||
          iclass == I[:movsx] || iclass == I[:movsxd] || iclass == I[:movzx] ||
          iclass == I[:bsf] || iclass == I[:bsr] || iclass == I[:xlat] ||
          # Extend value, handled like xfer, since access with implicit ops.
          iclass == I[:cbw] || iclass == I[:cwd] || iclass ==  I[:cwde] ||
          iclass == I[:cdq] || iclass == I[:cdqe] || iclass ==  I[:cqo] ||
          # far and near call
          iclass == I[:far_call] || iclass == I[:near_call]
        return true
      end
    end

    def cond_xfer?(iclass)
      if iclass == I[:cmovb]  || iclass == I[:cmovbe] || iclass == I[:cmovl] ||
          iclass == I[:cmovle]  || iclass == I[:cmovnb] || iclass == I[:cmovbe] ||
          iclass == I[:cmovnl]  || iclass == I[:cmovnle] || iclass == I[:cmovno] ||
          iclass == I[:cmovnp]  || iclass == I[:cmovns] || iclass == I[:cmovnz] ||
          iclass == I[:cmovo]  || iclass == I[:cmovp] || iclass == I[:cmovs] ||
          iclass == I[:cmovz]
        return true
      end
    end

    # Checks if the given instruction belongs to the group of ARITHMETIC
    # instructions.
    # @param i [Integer] instruction class
    # @param [Boolean] true if instruction belongs to ARITHMETIC, otherwise nil
    def arithmetic?(i)
      if zeroes_dst?(i) || shift?(i) ||
          i == I[:or] || i == I[:or] || i == I[:and] || i == I[:and_lock] ||
          i == I[:add] || i == I[:add_lock] || i == I[:adc] || i == I[:adc_lock]
        return true
      end
    end

    # Checks if the given instruction belongs to the one which potentially zeroes
    # out the destination. This method determines a pre-condition! To be sure one
    # has to do further checks (is src == dst).
    # @param i [Integer] instruction class
    # @param [Boolean] true if instruction potentially to be zeroed, otherwise nil
    def zeroes_dst?(i)
      return true if i == I[:xor] || i == I[:sub] || i == I[:sbb] ||
        i == I[:xor_lock] || i == I[:sub_lock] || i == I[:sbb_lock]
    end

    # Checks whether given instruction belongs to the group of SHIFT instructions.
    # @param i [Integer] instruction class
    # @param [Boolean] true if instruction belongs to SHIFT, otherwise nil
    def shift?(i)
      # rorl, ror, rorx.
      # shl, shld, shlx, shr, shrd, shrx
      # sar, sarx
      # rcl, rcr
      if i == I[:rorl] || i == I[:ror] || i == I[:rorx] ||
          i == I[:shl] || i == I[:shld] || i == I[:shlx] || i == I[:shr] ||
          i == I[:shrd] || i == I[:shrx] ||
          i == I[:sar] || i == I[:sarx] || i == I[:rcl] || i == I[:rcr]
        return true
      end
    end

    # Checks if the instruction is mul, idiv, mul or mulx aka braindead
    # instructions, which behave weirdly and need extra care.
    # @param i [Integer] instruction class
    # @param [Boolean] true if instruction belongs to mul/div/idiv, otherwise nil
    def pointer_arithmetic?(i)
      if i == I[:mul] || i == I[:mulx] || i == I[:imul] ||
          i == I[:div] || i == I[:idiv] || i == I[:xadd] || i == I[:xadd_lock]
        return true
      end
    end

    # Checks if the instruction is prefixed with a ret
    # @param i [Integer] instruction class
    # @param [Boolean] true if instruction is prefixed with rep, otherwise nil
    def rep_prefix?(i)
      if i == I[:ret_lodsb] || i == I[:ret_lodsd] || i == I[:ret_lodsq] ||
          i == I[:ret_lodsw] || i == I[:ret_stosb] || i == I[:ret_stosd] ||
          i == I[:ret_stosq] || I == I[:ret_stosw] || i == I[:ret_movsb] ||
          i == I[:ret_movsd] || i == I[:ret_movsq] || i == I[:ret_movsw] ||
          i == I[:lodsb] || i == I[:lodsd] || i == I[:lodsq] ||
          i == I[:lodsw] || i == I[:stosb] || i == I[:stosd] ||
          i == I[:stosq] || I == I[:stosw] || i == I[:movsb] ||
          i == I[:movsd] || i == I[:movsq] || i == I[:movsw]
        return true
      end
    end
  end
end
