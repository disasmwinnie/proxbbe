# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Helper Class for loops.
class Loop
  attr_reader :instructions, :start, :end, :type, :tainted_cmps, :c_jmps,
    :tainted_loop_head_index, :tainted_targets
  # Creates a loop. After freshly created it is an "open loop". It is finished, 
  # after instructions were added to it. Meaning, there was a repeated jmp.
  # @param loop_start [Integer] address of instruction _after_ jmp
  # @param loop_end [Integer] address instruction of relevant jmp or jcc
  # @param loop_type [Symbol] :c_jmp or :unc_jmp
  def initialize(loop_start, loop_end, loop_type)
    @start = loop_start
    @end = loop_end
    @type = loop_type
    # Array with instructions inside the loop body.
    @instructions = []
    # Amount of duplicate loops merged into this one.
    @duplicate_loop_count = 0
    # Holds all positions of tainted compares.
    @tainted_cmps = []
    @tainted_targets = []
    @c_jmps = []
    @unc_jmps = []
    @tainted = nil
    @tainted_loop_head_index = nil
  end

  def close
    # Create an Array of instructions.
    if @tainted_cmps.size == 0
      @c_jmps = nil
    elsif @type == :c_jmp && @tainted_cmps.last == (@c_jmps.last-1)
      @tainted = true
      @tainted_loop_head_index = @tainted_cmps.last
      @tainted_cmps = nil
      @c_jmp = nil
      return
    elsif @type == :unc_jmp
      @tainted_cmps.each do |t_cmp_index|
        # If there's tainted compare before the first conditional jmp, it's
        # the loop head!
        if t_cmp_index == (@c_jmps.first-1)
          @tainted = true
          @tainted_loop_head_index = t_cmp_index
          @tainted_cmps = nil
          @c_jmp = nil
          return
        end
      end
    end
    @tainted = false
  end

  # Adds instruction to the loop if it is within its boarders.
  # @param ins [Array] instruction
  def add_ins(ins)
    index_of_ins = @instructions.size
    if ins[0] == :cmp
      @tainted_cmps << index_of_ins
      @instructions << ins
    elsif ins[0] == :c_jmp
      @c_jmps << index_of_ins
      @instructions << ins
    elsif ins[0] == :misc && ins[2].tainted_ins? # && !ins[3].first['mr'].nil?
      # If mr and only mr is tainted.
      @tainted_targets << index_of_ins
      @instructions << ins
    end
  end

  # Checks if given instruction pointer is at the end of the loop.
  # @param ip [Integer] instruction pointer
  # @param loop_type [Symbol] :c_jmp or :unc_jmp, additional match, to be sure
  # it is relevant loop
  # @return [Boolean] true if given ip is the loop end
  def is_end?(ip, type)
    ip == @end && @type == type ? true : false
  end

  # Determines if the loop contains at least one tainted compare, which makes
  # the loop tainted.
  # @return [Boolean]
  def tainted?
    raise "Can't check an open loop for taint. Close it first." if @tainted.nil?
    return @tainted
  end

  # Override == to find Loops with same instructions.
  # @param l [Loop]
  # return [Boolean] true, if objects have same instructions/attributes
  def ==(l)
    # No need to check all instructions, following conditions are enough.
    if @start == l.start && @end == l.end &&
        @type == l.type && get_direction_field == l.get_direction_field
      return true
    else
      return false
    end
  end

  # Extract tainted compare instruction.
  # return [Range] direction field (tainted part loop head)
  def get_direction_field
    return @instructions[@tainted_loop_head_index][2].to_a
  end

  # Extract target fields.
  # @param addrs [Array] Integer array with relevant addresses
  # @return [Array] ranges with tainted operands of target instructions
  def get_target_fields_by(addr)
    possible_targets = []
    ins_addrs = []
    @tainted_targets.each do |tainted_target_index|
      ins_addr = @instructions[tainted_target_index][1]
      next if ins_addr != addr
      ins_addrs << ins_addr
      t_ops = @instructions[tainted_target_index][2].taint_labels
      if t_ops.any?
        t_ops.each do |t_addr, access_size|
          target_range = Range.new(t_addr, t_addr+access_size-1).to_a
          if target_range.first == get_direction_field.first &&
              target_range.last == get_direction_field.last
            next
          end
          # TODO: should check if this is not a MOV
          possible_targets += target_range if !target_range.empty?
        end
      end
      return possible_targets
    end
  end

  def get_target_addrs
    ins_addrs = []
    @tainted_targets.each do |tainted_target_index|
      ins_addrs << @instructions[tainted_target_index][1]
    end
    return ins_addrs.uniq
  end


  private
  # @!visibility private
  # Helper to retrieve the tainted address range of an operand.
  # @param op_name [String] operand name
  # @param t_ops [Array] tainted operands
  # @return [Range] tainted memory range of given operand, nil if not tainted
  def tainted_addr(op_name, t_ops)
    # Returns the tainted address if operand tainted, otherwise nil
    t_ops.each do |op|
      return op[op_name] if op[op_name]
    end
    return nil
  end


end

