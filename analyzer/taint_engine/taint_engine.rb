# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
require_relative '../utils/x86_reg'
include Tainting
require_relative '../utils/pin_iclass'
include Iclass::Tainting

# Takes one Trace object, interprets the tainted memory area. Spreads the
# taint through the trace and adds the tainted operators to every
# instructions.
#
# Following cases are relevant for tainting:
# - If Memory Read (mr) to into tainted area:
#   * Mark mr access as tainted.
#   * If Register Write (rw) then taint them.
# - If Memory Write (mw) to untainted area:
#   * If Register Read (rr) from tainted register, taint new memory area.
# - If Register Write (rw):
#   * Register Read (rr) from tainted register, then taint destination
#   register in case of rw.
#   * Register Read (rr) from untainted register, then check destination
#   register. If tainted, untaint.
class TaintEngine
  # Initializes TaintEngine with instance variables, later used to keep tainted
  # registers and memory areas.
  def initialize
    # Tainted memory is a list of range-objects.
    @t_mem = {}

    # Tainted registers.
    @t_regs = {}
  end

  # Add a tainted memory area to the TaintEngine. In the trace this is basically
  # the memory area where a packet landed.
  # @param buf_addr [Integer] packet buffer address
  # @param buf_count [Integer] length of the buffer
  def add_tainted_mem!(buf_addr, buf_count)
    tainted_by_packet = Range.new(buf_addr, (buf_addr + buf_count-1))
    tainted_by_packet.each do |addr|
      @t_mem[addr] = addr # replace old taint if necessary, don't care
    end
    $log.debug("Added tainted memory area to TaintEngine: #{tainted_by_packet}")
  end

  # Taint memory area by particular taint label.
  # This method, in contrast to add_tainted_mem! is used during taint spread.
  # @param buf_addr [Integer] packet buffer address
  # @param buf_count [Integer] length of the buffer
  # @param t_label [Integer] taint label
  def taint_mem!(buf_addr, buf_count, t_label)
    tainted_by_packet = Range.new(buf_addr, (buf_addr+buf_count-1))
    tainted_by_packet.each do |addr|
      @t_mem[addr] = t_label # replace old taint if necessary, don't care
    end
    $log.debug("Tainted memory area in TaintEngine: #{tainted_by_packet}")
  end

  # Deleted a tainted memory area in the the TaintEngine. Method is useful,
  # when tainted memory is overwritten with untainted data.
  # @param buf_addr [Integer] packet buffer address
  # @param buf_count [Integer] length of the buffer
  def untaint_mem!(buf_addr, buf_count)
    t_range = Range.new(buf_addr, (buf_addr + buf_count-1))
    t_range.each do |addr|
      @t_mem.delete(addr)
    end
    $log.debug("Deleted memory tags, addr: #{buf_addr}, len: #{buf_count}")
  end

  # Get taint lebel for particular address
  # @param addr [Integer] memory address of designated label
  # return [Integer] taint label if tainted, otherwise nil
  def taint_label_mem(addr)
    return @t_mem[addr]
  end

  # Processes an instruction state from the trace and determines if there where
  # access to tainted operand. Furthermore spreads the tainting accross its
  # runtime.
  # Tainting is implemented by working through following cases:
  #
  # 1) t_mr -> u_rr taintet mem_read to register. CASE WRONG! u_rr is READ
  # Access.
  # 2) t_mr -> u_rw tainted mem_read to register, taint register with mem
  # range.
  # 3) t_mr -> t_mw some opcode like "inc [rax]" do this, no repeating of
  # tainting.
  # needed for same address, just note a tainted write.
  # 4) untainted mr -> X, but base or index is tainted. Handle as t_mr.
  #
  # Also untainted access to tainted regs/memory relevant. In both cases
  # memory/reg must be untainted:
  # 5) u_mr -> t_rw
  # 6) u_mr -> t_mw NO SUCH CASE in x86
  #
  # 7) t_rr && u/t_rr only one can be tainted or both, e.g. cmp.
  # 8) t_rr -> u/t_rw tainted reg read to register,
  #         untaint rw if tainted, taint with new range
  # 9) t_rr -> u/t_ mw
  #
  # Same here for untaitned register read:
  # 10) u_rr && t_rr <--- Special case!
  # 11) u_rr -> t_rw
  # 12) u_rr -> t_mw
  #
  # Immediate values are always untainted, so they can replace already tainted
  # registers or memory areas.
  # 13) imm -> t_rw un-taint destination register
  # 13) imm -> t_mw un-taint destination memory area
  #
  # Prepare accessed operands (clean assigning to variables).
  # @param is [InstructionState] instruction state from the trace
  # @return [Array] tainted operands as Hash with access type as kye and
  # tainted address range as value.
  def get_tainted_ops(is)

    $log.debug("List of tainted registers: #{@t_regs.inspect}")
    # Handle CMPSx specially
    if multiple_mr?(is.iclass)
      handle_cmpsx(is)
      return
    end

    # Check for tainted base and index. They can be tainted even if the
    # calculated result is not a tainted memory address.
    if is.m_base && tainted_reg?(is.m_base[0])
      is.t_m_base = taint_label_reg(is.m_base[0])
    end
    if is.m_index && tainted_reg?(is.m_index[0])
      is.t_m_index = taint_label_reg(is.m_index[0])
    end

    if (is.t_action == TaintAction::CLEAR_REG) ||
        (is.t_action == TaintAction::UNION && zeroes_dst?(is.iclass) && is.rw &&
         is.rr.size >= 2 && is.rw[0] == is.rr[1][0] &&
         tainted_reg?(is.rr[1][0]))

      # either SETcc or something like xor eax, eax
      if is.rw && tainted_reg?(is.rw[0])
        untaint_reg!(is.rw[0])
        $log.debug("Untainted #{is.rw[0]} during RIP #{is.regs['rip']}, by: " +
                   "#{is.t_action}")
      end
      # E.g. STR
      if is.mw && tainted_mem?(is.mw[0],is. mw[1])
        untaint_mem!(is.mw[0], is.mw[1])
        $log.debug("Untainted mem #{is.mw} during RIP #{is.regs['rip']}" +
                   ", by #{is.t_action}")
      end
      return
    elsif is.t_action == TaintAction::CLEAR_MULT_REG
      is.rw.each do |written_reg|
        untaint_reg!(written_reg[0]) if tainted_reg?(written_reg[0])
      end
    elsif is.t_action == TaintAction::POINTER_ARITHMETIC
      t_label = 0
      if is.mr && tainted_mem?(is.mr[0], is.mr[1])
        t_label |= taint_label_mem(is.mr[0])
        is.t_mr = t_label
      end

      if is.rr[0] && tainted_reg?(is.rr[0][0])
        t_label |= taint_label_reg(is.rr[0][0])
        is.t_rr[0] = t_label
      end

      if is.rr[1] && tainted_reg?(is.rr[1][0])
        t_label |= taint_label_reg(is.rr[1][0])
        is.t_rr[1] = t_label
      end

      is.rw.each do |written_reg|
        reg_label = 0
        if tainted_reg?(written_reg[0])
          reg_label = taint_label_reg(written_reg[0])
          untaint_reg!(written_reg[0])
        end
        t_label |= reg_label
        taint_reg!(written_reg[0], t_label) if t_label != 0
      end

      # sometimes the case for xadd instruction
      if is.mw
        taint_mem!(is.mw[0], is.mw[1], t_label)
      end

      return
    elsif is.t_action == TaintAction::LEA
      t_label = 0
      dst_tainted = tainted_reg?(is.rw[0])
      if is.m_base && tainted_reg?(is.m_base[0])            # Case 4a)
        if dst_tainted
          t_r2t_r(is.m_base, is.rw, TaintAction::UNION)
        else
          t_r2u_r(is.m_base, is.rw, TaintAction::UNION)
        end
        # THIS CASE DOES NOTHING, HENCE COMMENTED. Intentionally left for clarity.
        #elsif is.m_base && dst_tainted
        #  u_r2t_r(is.rw, TaintAction::UNION)
      end
      if is.m_index && tainted_reg?(is.m_index[0])          # Case 4b)
        if dst_tainted
          t_r2t_r(is.m_index, is.rw, TaintAction::UNION)
        else
          t_r2u_r(is.m_index, is.rw, TaintAction::UNION)
        end
        # THIS CASE DOES NOTHING, HENCE COMMENTED. Intentionally left for clarity.
        #elsif is.m_index && dst_tainted
        #  u_r2t_r(is.rw, TaintAction::UNION)
      end
      return
    elsif is.t_action == TaintAction::LEAVE
      # Kind of alias for two instructions, we execute the first by hand and
      # prepare the operands so the rest of the taint engine takes care of the
      # second.
      # mov Xsp, Xbp
      # First, clean implicit registers of the mov. Source is ebp or rbp.
      is.rr.delete_if { |read_reg| !read_reg[0].include?('bp') }
      is.rw.delete_if { |written_reg| !written_reg[0].include?('sp') }
      if tainted_reg?(is.rr[0][0])
        if tainted_reg?(is.rw[0][0])
          t_r2t_r(is.rr[0], is.rw[0], TaintAction::XFER)
        else
          t_r2u_r(is.rr[0], is.rw[0], TaintAction::XFER)
        end
      elsif tainted_reg?(is.rw[0][0])
        u_r2t_r(is.rw[0], TaintAction::XFER)
      end
      # pop Xbp
      is.rw = is.rr[0]
      is.rr = []
      is.t_action = TaintAction::XFER
    elsif is.t_action == TaintAction::ENTER
      # Kind of alias for two instructions, we execute the first by hand and
      # prepare the operands so the rest of the taint engine takes care of the
      # second.
      # push Xbp
      xbp = nil
      is.rr.each { |read_reg| xbp = read_reg if read_reg[0].include?('bp') }
      if tainted_reg?(xbp[0])
        if tainted_mem?(is.mw[0], is.mw[0])
          t_r2t_m(xbp, is.mw, TaintAction::XFER)
        else
          t_r2u_m(xbp, is.mw, TaintAction::XFER)
        end
      else
        if tainted_mem?(is.mw[0], is.mw[0])
          u_r2t_m(is.mw, TaintAction::XFER)
        end
      end

      # mov Xbp, Xsp
      is.rr.delete_if { |read_reg| !read_reg[0].include?('sp') }
      is.rw.delete_if { |written_reg| !written_reg[0].include?('bp') }
      is.mw = nil
      is.t_action = TaintAction::XFER
    elsif is.t_action == TaintAction::XCHG
      # 1. Get labels of both operands
      # 2. Untaint both, if tainted
      # 3. Exchange labels, if they are set
      r0_label = 0
      r0_label = taint_label_reg(is.rr[0][0]) if tainted_reg?(is.rr[0][0])
      untaint_reg!(is.rr[0][0]) if r0_label != 0
      # can be either memory and one register or two registers
      # In both cases rr[i] and rw[i] are both the same respectivaly mr == mw
      if is.mr && is.mw && is.rr.size == 1 && is.rw.size == 1
        m_label = 0
        if tainted_mem?(is.mr[0], is.mr[1])
          m_label = taint_label_mem(is.mr[0])
          is.t_mr = m_label
        end
        untaint_mem!(is.mr[0], is.mr[1]) if m_label != 0

        taint_reg!(is.rr[0][0], m_label) if m_label != 0
        taint_mem!(is.mr[0], is.mr[1], r0_label) if r0_label != 0
      elsif is.rr.size == 2 && is.rw.size == 2
        r1_label = 0
        r1_label = taint_label_reg(is.rr[1][0]) if tainted_reg?(is.rr[1][0])
        untaint_reg!(is.rr[1][0]) if r1_label != 0

        taint_reg!(is.rr[0][0], r1_label) if r1_label != 0
        taint_reg!(is.rr[1][0], r0_label) if r0_label != 0
      else
        raise "Unpredicted case for state #{is.inspect}"
      end

      # save read operands
      if is.mr && tainted_mem?(is.mr[0], is.mr[1])
        is.t_mr = taint_label_mem(is.mr[0])
      end

      if is.rr[0] && tainted_reg?(is.rr[0][0])
        is.t_rr[0] = taint_label_reg(is.rr[0][0])
      end
      if is.rr[1] && tainted_reg?(is.rr[1][0])
        is.t_rr[1] = taint_label_reg(is.rr[1][0])
      end

      return
    elsif is.t_action == TaintAction::REP_PREFIX
      # For rep instructions we need to clear the access to the counter
      # register. Afterwards the operands are unambiguous for taint spreading.
      is.rw = nil
      is.rr.delete_if { |read_reg| read_reg[0].include?('c') }
      is.t_action = TaintAction::XFER
      raise "REP cleaning failed: #{is.inspect}" if is.rr.size > 1
    end

    # At this point wie continue with XFER, UNION tainting actions or, with
    # NOTHING. Which doesn't spreads taint. Still return of tainted operands
    # is possible.
    ### copy of immediate ###
    if is.imm
      if is.rw && tainted_reg?(is.rw[0])
        imm2t_r(is.rw, is.t_action)
      elsif is.mw && tainted_mem?(is.mw[0], is.mw[1])
        imm2t_m(is.mw, is.t_action)
      elsif is.rr.size >= 1 && tainted_reg?(is.rr[0][0])
        # Mostly CMP
        is.t_rr[0] = taint_label_reg(is.rr[0][0])
      elsif is.mr && tainted_mem?(is.mr[0], is.mr[1])
        is.t_mr = taint_label_mem(is.mr[0])
      elsif is.rr.size >= 2
        # This can happen with extensions' instructions like:
        # vpcmpistri xmm0, xmm1, 0x1a
        $log.warn("WTF is this instruction? #{is.inspect}")
      end
      return
    end
    ### copy of immediate ###

    ### memory read ###
    if is.mr
      if tainted_mem?(is.mr[0], is.mr[1])
        is.t_mr = taint_label_mem(is.mr[0])
        if is.rw                                        # Case 2)
          if tainted_reg?(is.rw[0])
            t_m2t_r(is.mr, is.rw, is.t_action)
          else
            t_m2u_r(is.mr, is.rw, is.t_action)
          end
        elsif is.mw                                    # Case 3)
          if tainted_mem?(is.mw[0], is.mw[1])
            t_m2t_m(is.mr, is.mw, is.t_action)
          else
            t_m2u_m(is.mr, is.mw, is.t_action)
          end
        end
      else
        if is.rw && tainted_reg?(is.rw[0])                # Case 5)
          u_m2t_r(is.rw, is.t_action)
        elsif is.mw && tainted_mem?(is.mw[0], is.mw[1])
          u_m2t_m(is.mw, is.t_action)
        end
      end
      return
    end
    ### memory read ###

    ### register read ###
    if is.rr.size >= 1
      # Cases 8,9,11,12)
      t_label = handle_tainted_rr(is.rr[0], is.t_action, is.rw, is.mw)
      is.t_rr[0] = t_label if t_label
      if is.rr.size == 2
        # Case 7, 10)
        t_label = handle_tainted_rr(is.rr[1], is.t_action, is.rw, is.mw)
        is.t_rr[1] = t_label if t_label
      end
    end
    return
    ### register read ###
  end

  private
  # @!visibility private
  # Helper method (outsourced to make tainting routine readable) which handles
  # the cases 7,8,9,10,11,12 (see #get_tainted_ops).
  # @param rr [Array] register read operands (if any)
  # @param t_action [TaintAction] enum with tainting action
  # @param rw [Hash] written register operand, if exists
  # @param mw [Hash] written memory operand, if exists
  # @return [Integer] tainted label
  def handle_tainted_rr(rr, t_action, rw=nil, mw=nil)
    t_label = nil
    if tainted_reg?(rr[0])                                     # Case 7,8,10)
      t_label = taint_label_reg(rr[0])
      if rw                                                    # More on Case 8)
        if tainted_reg?(rw[0])
          t_r2t_r(rr, rw, t_action)
        else
          t_r2u_r(rr, rw, t_action)
        end
      elsif mw                                                # Case 9)
        if tainted_mem?(mw[0], mw[1])
          t_r2t_m(rr, mw, t_action)
        else
          t_r2u_m(rr, mw, t_action)
        end
      end
    else
      if rw && tainted_reg?(rw[0])                            # Case 11)
        u_r2t_r(rw, t_action)
      elsif mw && tainted_mem?(mw[0], mw[1])             # Case 12)
        u_r2t_m(mw, t_action)
      end
    end
    return t_label
  end

  # @!visibility private
  # Helper method for to get addresses a register is tainted by.
  # @param reg [String] register name
  # @return [Range] address range the register was tainted by
  def taint_label_reg(reg)
    reg_sym = reg.to_sym
    # Return a tainted label of the given register or a sub register of it,
    # since it also would "contaminate" value of register slice ahead. E.g.,if
    # rcx is read, but only cx is tainted (not rcx), the return label of cx.
    all_reg_parts(reg_sym).each do |sub_reg|
      return @t_regs[sub_reg] if !@t_regs[sub_reg].nil?
    end
  end

  # @!visibility private
  # Helper method to check if a memory area, used as operand, is tainted.
  # @param addr [Integer] memory address
  # @param access_size [Integer] memory access size
  # @return [Boolean] true if memory area tainted
  def tainted_mem?(addr, access_size)
    if taint_label_mem(addr) && taint_label_mem(addr + access_size-1)
      return true
    elsif taint_label_mem(addr)
      $log.warn("Possible miscalculation of addresses or ambigious memory" +
                "access like movzx uses it.")
      return true
    else
      return false
    end
  end

  # @!visibility private
  # Helper Method to check if a register, used as operand, is tained.
  # @param reg [String] register name
  # @return [Boolean] true if register is tainted
  def tainted_reg?(reg)
    # The method is syntax sugar for:
    reg_sym = reg.to_sym
    all_reg_parts(reg_sym).each do |sub_reg|
      return true if @t_regs.include?(sub_reg)
    end
    return false
  end

  # @!visibility private
  # Syntax sugar wrapper for #un_taint_reg.
  # @param reg [String] register name
  def untaint_reg!(reg)
    un_taint_reg(reg, taint=false)
    $log.debug("Untainted register: #{reg}")
  end

  # @!visibility private
  # Syntax sugar wrapper for #un_taint_reg.
  # @param reg [String] register name
  # @param l [Integer] label to taint register with
  def taint_reg!(reg, l)
    un_taint_reg(reg, label=l, taint=true)
    $log.debug("Tainted register: #{reg} with label: #{label}")
  end

  # @!visibility private
  # Helper method to tainte or untaint a tainted register.
  # @param reg [String] register name to be un-/tainted
  # @param label [Range] memory range to taint a register with, can be nil in
  # case of untaint
  # @param taint [Boolean] determines whether the method is used for taint or
  # untaint
  def un_taint_reg(reg, label=nil, taint=false)
    #
    # Helper method to DRY up the taint and untaint_reg methods.
    #
    raise "A memory range is needed for tainting!" if taint && label.nil?

    # A reg access looks like this: ["esi", 4], hence value[0]
    regs_to_taint = write_to(reg)
    regs_to_taint.each do |r|
      if taint
        @t_regs[r] = label
      else
        @t_regs.delete(r)
      end
    end
  end

  # @!visibility private
  # Helper method to handle immediate to tainted register write.
  # @param rw [Array] written register operand
  # @param t_action [Integer] taint action
  def imm2t_r(rw, t_action)
    case t_action
    when TaintAction::NOTHING, TaintAction::UNION
      return # Do nothing, since no taint spreading/untainting possible.
    when TaintAction::XFER
      untaint_reg!(rw[0])
      $log.debug("Untaint register #{rw}, due immediate by: #{t_action}")
    end
  end

  # @!visibility private
  # Helper method to handle immediate to tainted memory write.
  # @param mw [Array] written memory operand
  # @param t_action [Integer] taint action
  def imm2t_m(mw, t_action)
    case t_action
    when TaintAction::NOTHING, TaintAction::UNION
      return # Do nothing, since no taint spreading/untainting possible.
    when TaintAction::XFER
      untaint_mem!(mw[0], mw[1])
      $log.debug("Untaint memory #{mw}, due immediate by: #{t_action}")
    end
  end

  # @!visibility private
  # Helper method to handle tainted memory read to untainted register write.
  # @param mr [Array] read memory operand
  # @param rw [Array] written register operand
  # @param t_action [Integer] taint action
  def t_m2t_r(mr, rw, t_action)
    case t_action
    when TaintAction::NOTHING
      return
    when TaintAction::XFER
      untaint_reg!(rw[0])
      taint_reg!(rw[0], taint_label_mem(mr[0]))
    when TaintAction::UNION
      m_label_src = taint_label_mem(mr[0])
      r_label_dst = taint_label_reg(rw[0])
      untaint_reg!(rw[0])
      r_label_dst |= m_label_src
      taint_reg!(rw[0], r_label_dst)
    end
  end

  # @!visibility private
  # Helper method to handle tainted memory read to untainted register write.
  # @param mr [Array] read memory operand
  # @param rw [Array] written register operand
  # @param t_action [Integer] taint action
  def t_m2u_r(mr, rw, t_action)
    case t_action
    when TaintAction::NOTHING
      return
    when TaintAction::XFER, TaintAction::UNION
      taint_reg!(rw[0], taint_label_mem(mr[0]))
    end
  end

  # @!visibility private
  # Helper method to handle tainted memory read to tainted memory write.
  # Used for instructions like movsb.
  # @param mr [Array] read memory operand
  # @param mw [Array] written memory operand
  # @param t_action [Integer] taint action
  def t_m2t_m(mr, mw, t_action)
    case t_action
    when TaintAction::NOTHING
      return
    when TaintAction::XFER
      taint_mem!(mw[0], mw[1], taint_label_mem(mr[0]))
    when TaintAction::UNION
      m_label_src = taint_label_mem(mr[0])
      m_label_dst = taint_label_mem(mw[0])
      m_label_dst |= m_label_src
      taint_mem!(mw[0], mw[1], m_label_dst)
    end
  end

  # @!visibility private
  # Helper method to handle tainted memory read to untainted memory write.
  # Used for instructions like movsb.
  # @param mr [Array] read memory operand
  # @param mw [Array] written memory operand
  # @param t_action [Integer] taint action
  def t_m2u_m(mr, mw, t_action)
    case t_action
    when TaintAction::NOTHING
      return
    when TaintAction::XFER, TaintAction::UNION
      taint_mem!(mw[0], mw[1], taint_label_mem(mr[0]))
    end
  end

  # @!visibility private
  # Helper method to handle untainted memory read to tainted memory write.
  # @param mw [Array] written memory operand
  # @param t_action [Integer] taint action
  def u_m2t_m(mw, t_action)
    if t_action == TaintAction::XFER
      # only relevant for string copy like movsb
      untaint_mem!(mw[0], mw[1])
    end
  end

  # @!visibility private
  # Helper method to handle untainted memory read to tainted register write.
  # @param rw [Array] written register operand
  # @param t_action [Integer] taint action
  def u_m2t_r(rw, t_action)
    case t_action
    when TaintAction::NOTHING, TaintAction::UNION
      return
    when TaintAction::XFER
      untaint_reg!(rw[0])
    end
  end

  # @!visibility private
  # Helper method to handle tainted register read to tainted register write.
  # @param rr [Array] read register operand
  # @param rw [Array] written register operand
  # @param t_action [Integer] taint action
  def t_r2t_r(rr, rw, t_action)
    case t_action
    when TaintAction::NOTHING
      return
    when TaintAction::XFER
      r_label = taint_label_reg(rr[0])
      untaint_reg!(rw[0])
      taint_reg!(rw[0], r_label)
    when TaintAction::UNION
      # OR the src and dst label
      r_label_src = taint_label_reg(rr[0])
      r_label_dst = taint_label_reg(rw[0])
      untaint_reg!(rw[0])
      r_label_dst |= r_label_src
      taint_reg!(rw[0], r_label_dst)
    end
  end

  # @!visibility private
  # Helper method to handle tainted register read to untainted register write.
  # @param rr [Array] read register operand
  # @param rw [Array] written register operand
  # @param t_action [Integer] taint action
  def t_r2u_r(rr, rw, t_action)
    case t_action
    when TaintAction::NOTHING
      return
    when TaintAction::XFER, TaintAction::UNION
      # Copy and an OR of destination is in this case the same.
      r_label = taint_label_reg(rr[0])
      taint_reg!(rw[0], r_label)
    end
  end

  # @!visibility private
  # Helper method to handle tainted register read to tainted memory write.
  # @param rr [Array] read register operand
  # @param mw [Array] written memory operand
  # @param t_action [Integer] taint action
  def t_r2t_m(rr, mw, t_action)
    case t_action
    when TaintAction::NOTHING # avoid further checks.
      return
    when TaintAction::XFER
      r_label = taint_label_reg(rr[0])
      taint_mem!(mw[0], mw[1], r_label)
    when TaintAction::UNION
      r_label_src = taint_label_reg(rr[0])
      m_label_dst = taint_label_mem(rw[0])
      m_label_dst |= r_label_src
      taint_mem!(new_mem_label, mw[1])
    end
  end

  # @!visibility private
  # Helper method to handle tainted register read to untainted memory write.
  # @param rr [Array] read register operand
  # @param mw [Array] written memory operand
  # @param t_action [Integer] taint action
  def t_r2u_m(rr, mw, t_action)
    case t_action
    when TaintAction::NOTHING # avoid further checks.
      return
    when TaintAction::XFER, TaintAction::UNION
      r_label = taint_label_reg(rr[0])
      taint_mem!(mw[0], mw[1], r_label)
    end
  end

  # @!visibility private
  # Helper method to handle untainted register read to tainted register write.
  # @param rw [Array] written register operand
  # @param t_action [Integer] taint action
  def u_r2t_r(rw, t_action)
    case t_action
    # Other cases are irrelevant, e.g., TaintAction::UNION needs no action.
    when TaintAction::NOTHING, TaintAction::UNION # avoid further checks.
      return
    when TaintAction::XFER
      untaint_reg!(rw[0])
    end
  end

  # @!visibility private
  # Helper method to handle untainted register read to tainted memory write.
  # @param mw [Array] written memory operand
  # @param t_action [Integer] taint action
  def u_r2t_m(mw, t_action)
    case t_action
      # Other cases are irrelevant, e.g., TaintAction::UNION needs no action.
    when TaintAction::NOTHING, TaintAction::UNION # avoid further checks.
      return
    when TaintAction::XFER
      untaint_mem!(mw[0], mw[1])
    end
  end

  # @!visibility private
  # Helper method to handle CMPSx instructions, which have other operand
  # combinations then most instructions.
  # param is [InstructionState]
  def handle_cmpsx(is)
    if tainted_mem?(is.mr[0][0], is.mr[0][1])
      t_label = taint_label_mem(is.mr[0][0])
      is.t_mr[0] = t_label
    end
    if tainted_mem?(is.mr[1][0], is.mr[1][1])
      t_label = taint_label_mem(is.mr[1][0])
      is.t_mr[1] = t_label
    end

    if tainted_reg?('rsi')
      is.t_m_base[0] = taint_label_reg('rsi')
    end
    if tainted_reg?('rdi')
      is.t_m_base[1] = taint_label_reg('rdi')
    end
  end
end

