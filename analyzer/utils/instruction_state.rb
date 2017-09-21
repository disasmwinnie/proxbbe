# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Represents an InstructionState from a json line. Offers easy access to its
# information.
require_relative '../utils/pin_iclass'
include Iclass::Tainting
class InstructionState
  attr_reader :mr, :mw, :imm, :m_base, :m_index, :iclass, :regs
  attr_accessor :t_action, :rr, :rw, :t_rr, :t_rw, :t_mr, :t_mw, :t_m_base,
    :t_m_index



  # Constructor for an InstructionState.
  # Takes a json line representation and parses it to enable easy access to
  # variables.
  # @param ins_state_orig [String] InstructionState as jsonl
  def initialize(ins_state_orig)
    ins_state = ins_state_orig.dup
    @iclass = ins_state['iclass']
    @regs = ins_state['regs']
    @t_action = Iclass::analyze_iclass(@iclass, @regs['flags'])

    # this is purely for debugging/verbosity
    @instr = ins_state['instruction']

    @rr = []
    @t_rr = Array.new(2)
    @rw = nil
    @t_rw = nil
    if multiple_rw?(@t_action) # needs not iclass, but t_action!
      @rw = []
      @t_rw = Array.new(2)
    end
    @mr = nil
    @t_mr = nil
    @m_base = nil
    @t_m_base = nil
    @m_index = nil
    @t_m_index = nil

    if multiple_mr?(@iclass)
      @mr = []
      @t_mr = Array.new(2)
      @m_base = []
      @t_m_base = Array.new(2)
    end
    @mw = nil
    @t_mw = nil
    @imm = nil
    ins_state['op_access'].each do |op|
      # skip (r)flags access
      next if (op['rw'] && op['rw'][0].include?('flag'))  ||
        (op['rr'] && op['rr'][0].include?('flag'))

      @rr << op['rr'] if op['rr']
      # point arithmetic instruction have multiple destinations
      if op['rw'] && !@rw.nil?
        @rw << op['rw']
      elsif op['rw']
        @rw = op['rw']
      end

      if op['mr']
        if multiple_mr?(@iclass)
          @mr << op['mr']
        else
          @mr = op['mr']
        end
      end
      if op['mw']
        @mw = op['mw']
        @mw[0] = @mw[0]
      end

      @imm = op['imm'] if op['imm']
      if multiple_mr?(@iclass)  # CMPx instructions, no multiple index regs
        @m_base << ['m_base'] if op['m_base']
      else
        @m_base = op['m_base'] if op['m_base']
      end
      @m_index = op['m_index'] if op['m_index']
    end
  end

  # Check if this instruction has any tainted parameters.
  # @return [Boolean] true if there is at least one tainted operand
  def tainted_ins?
    if multiple_mr?(@iclass)
      if !@t_mr[0].nil? || !@t_mr[1].nil?
        return true
      end
    elsif !@t_rr[0].nil? || !@t_rr[1].nil? ||
        @t_mr # || @t_m_base || @t_m_index
      return true
    else
      return false
    end
  end

  # Get taint labels along with their access sizes. Ignores tainted index
  # and base registers.
  # @return [Array] taint labels
  def taint_labels
    labels = []
    return labels if !tainted_ins?

    # This "could" be incorrect if @rr.size == 2 and @t_rr.size == 1.
    # However, I don't see an easy way to deside wether @t_rr[0] belongs to
    # @rr[0] or to @rr[1]. However in pretty much most cases the access size
    # of both operands is the same. An exception to this is something like
    # movzx. If you use this method for memory accesses, you hopefully don't use
    # MOVs of anykind at all.
    if !@t_rr[0].nil? && !@rr[0].nil?
      labels << [@t_rr[0], @rr[0][1]]
    end
    if !@t_rr[1].nil?  && !@rr[1].nil?
      labels << [@t_rr[1], @rr[1][1]]
    end
    if @t_rw
      if !@t_rw[0].nil?
        labels << [@t_rw[0], @rw[0][1]]
      end
      if !@t_rw[1].nil?
        labels << [@t_rw[1], @rw[1][1]]
      end
    end
    if multiple_mr?(@iclass)
      if !@t_mr[0].nil?
        labels << [@t_mr[0], @mr[0][1]]
      end
      if !@t_mr[1].nil?
        labels << [@t_mr[1], @mr[1][1]]
      end
    elsif !@t_mr.nil?
      labels << [@t_mr, @mr[1]]
    end

    return labels
  end

  # Helper to check whether as state is relevant for delimited or
  # keyword fields. If no, returns nil, else returns the compared values.
  # The first returned operand is always the tainted memory address and the
  # second the non- tainted fixed value compared against.
  # For a successful match there has to be exactly one tainted operand
  # read-access. Both operands can be from the group {rr, imm, mr}, whereas at
  # least one operand must be rr or mr. Both can't be imm (makes no sence in
  # this case) and both can't be mr (x86 limitation).
  # @return [Array] with two elements, the first is a memory range the operand
  # was tainted with and the second value a non-tainted value of the second
  # operand. Returns nil, if the instruction doesn't qualify for delimiter
  # inference (no tainted operands or both operands tainted).
  def cmp_range_and_value
    if !tainted_ins?
      return nil
    end

    if !(compare?(@iclass) || zero_compare?(@iclass) || multiple_mr?(@iclass))
      return nil
    end

    # Handle cmpsX in a special manner
    if multiple_mr?(@iclass)
      d_a_k = Array.new(2)
      if @t_mr[0] && @t_mr[1] # only one op must be tainted.
        return nil
      elsif @t_mr[0]
        d_a_k[0] = @t_mr[0]
      elsif @t_mr[1]
        d_a_k[0] = @t_mr[1]
      end
      # We cant find out the value of the memory. That's a limitation, however,
      # this doesn't play a great role, since we have the message content at
      # the of the output.
      d_a_k[1] = 0
      return d_a_k
    end

    # cmpXCHG instructions mess up the operands and therefore are in need of
    # cleaning up. Ugly hack, but necessary.
    if xchg_compare?(@iclass)
      index_rr2delete = nil
      @rr.each_with_index do |r,i|
        if r == @rw
          index_rr2delete = i
          break
        end
      end
      @rr.delete_at(index_rr2delete)
    end

    # Additional check for zero compare needed after operands parsed.
    # If successful, then preprocess operands so one operand compared against
    # zero.
    if zero_compare?(@iclass)
      if @rr.size == 2 && rr[0] == rr[1] # the only case we interested in
        # Compare one register against value zero.
        @rr.delete_at(1)
        imm = 0
      else
        return nil
      end
    end

    d_a_k = Array.new(2)
    # Following cases for operands are possible:
    #   - 1) rr : rr
    #   - 2) rr : mr
    #   - 3) rr : imm
    #   - 4) mr : imm

    if @rr.size >= 1

      # If first register tainted, then it's first element of d_a_k array.
      d_a_k[0] = @t_rr[0]
      if d_a_k[0].nil?
        # get value of non-tainted register
        reg_64name = Inference.get_64_reg(@rr[0][0])
        reg_value_unfiltered = @regs[reg_64name]
        d_a_k[1] = Inference.reg_value(@rr[0][0], reg_value_unfiltered)
      end


      if @rr.size >= 2         # case 1)
        # only one tainted register allowed
        if !@t_rr[0].nil? && !@t_rr[1].nil?
          return nil
        end

        if d_a_k[0].nil?
          # Means there are no tainted registers, should not happend at this
          # point.
          if @t_rr[1].nil?
            raise "Both registers are untainted. Something went wrong!"
          else
            d_a_k[0] = @t_rr[1]
          end
        else
          reg_64name = Inference.get_64_reg(@rr[1][0])
          reg_value_unfiltered = @regs[reg_64name]
          d_a_k[1] = Inference.reg_value(@rr[1][0], reg_value_unfiltered)
        end

      elsif @mr                # case 2)
        if @t_mr # mr tainted?
          d_a_k[0] = @t_mr
        elsif !d_a_k[0].nil? # At this point there must have been a tainted reg
          d_a_k[1] = Range.new(@mr[0], mr[0]+mr[1]-1)
        else # Otherwise operands untainted
          return nil
        end
      elsif @imm && !d_a_k[0].nil?  # case 3). Again a tainted reg required
        # Immediate is always untainted
        d_a_k[1] = @imm[0]
      else
        return nil
      end
    elsif @t_mr && @imm           # case 4)
      # Immediate can't be tainted.
      d_a_k[0] = @t_mr
      # if not one byte comparison, then not relevant.
      d_a_k[1] = @imm[0]
    else
      # Should'n happen. Even though Chap. 7.3.2.4 states CMP is between two
      # $IMM_VALUE (regardless of source), this case is exclude with
      # "if state['t_access'].size != 1" check at the beginning of the method.
      # Write-access is also excluded  beforehand.
      raise "Invalid case or two immediates are compared."
    end

    # Last sanity check.
    if d_a_k[0].nil? || d_a_k[1].nil?
      throw "Failed delimiter or key check."
    end

    return d_a_k
  end

  # Overwritten inspect method for debug and verbosity.
  # return [String] information about InstructionState object
  def inspect
    str = "iclass: #{@iclass}, action number: #{t_action}\nInstr: #{@instr}\n" +
      "registers: #{@regs}\nOperands:\n" +
      "\t rr: #{@rr}, t_rr: #{@t_rr}, rw: #{@rw}, t_rw: #{@t_rw} " +
      "\t mr: #{@mr}, t_mr: #{@t_mr}, immediate: #{@imm}"
    return str
  end

end
