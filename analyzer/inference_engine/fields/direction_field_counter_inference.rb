# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Responsible of inference of direction and their targets. This infers counter
# direction/target fields.
require_relative 'abstract_field_inference'
require_relative '../../utils/pin_iclass'
require_relative 'Loop'
include Iclass::Inference

class DirectionFieldCounterInference < AbstractFieldInference
  # Constructor, initializes internal objects for all subclasses involved in the
  # inference step.
  def initialize
    # Instruction stack
    @ins_queue = []

    # Potential loops. Must be examined whether they are tainted.
    @open_loops = []

    # Extracted, unique loops.
    @loops = []

    # Flag to find out whether a jump happend in the previous example.
    # This is handy skip unnecessary checks for loops.
    @found_jmp = false

    # The end results
    @dir_tar_fields = nil
  end


  def analyze_state(is, cmp)
    # Record last instructions
    cur_ip = is.regs['rip']
    ins = nil
    if cmp
      op_size = 0
      if multiple_mr?(is.iclass)
        op_size = is.mr[0][1]  # the first op is smaller/correct (PIN weirdness)
      elsif is.mr
        op_size = is.mr[1]
      elsif is.rr.size > 0
        op_size = is.rr[0][1]  # rr[0] or rr[1] has alwasy same size
      end

      raise 'Invalid tainted operand. Size not found.' if op_size == 0
      ins = [:cmp, cur_ip, Range.new(cmp[0], cmp[0]+op_size-1), cmp[1]]
    elsif cond_jmp?(is.iclass)
      ins = [:c_jmp, cur_ip]
      @found_jmp = true
    elsif uncond_jmp?(is.iclass)
      ins = [:unc_jmp, cur_ip]
      @found_jmp = true
    else
      ins = [:misc, cur_ip, is]
    end
    @ins_queue << ins
    add_ins_to_open_loops(ins)
    check_for_loops if @found_jmp
  end

  # Basically check for for all types of loops we can identify.
  # There are basically two kind of loops:
  # - A cmp and a conditional jmp to lower address.
  # - A cmp and conditional jmp forwards to a higher address. Additionally,
  # between the target address and the address of the conditional jmp, there has
  # to be an un-conditional jmp.
  def check_for_loops

    # We need one instruction after the jmp to know where it jumps to.
    last_ins = @ins_queue[-1]
    next_to_last_ins = @ins_queue[-2]
    if @ins_queue.size >= 1 &&
        (last_ins[0] == :c_jmp || last_ins[0] == :unc_jmp)
      index_of_open_loop = is_end_of_loop?(last_ins[1], last_ins[0])
      if index_of_open_loop
        open_loop = @open_loops.delete_at(index_of_open_loop)
        open_loop.close
        add_loop(open_loop)
        if @open_loops.empty? # This is non-empty if there are nested loop(s).
          @ins_queue = []
          @found_jmp = false
        end
      end
    elsif @ins_queue.size >= 2 &&
      (next_to_last_ins[0] == :c_jmp || next_to_last_ins[0] == :unc_jmp)
      # does it jump back?
      if next_to_last_ins[1] > last_ins[1]
        loop_start = last_ins[1]
        loop_end = next_to_last_ins[1]
        loop_type = next_to_last_ins[0]
        new_open_loop = Loop.new(loop_start, loop_end, loop_type)
        new_open_loop.add_ins(last_ins)
        @open_loops << new_open_loop
        @ins_queue = []
      end
    end
  end

  # Determines if the given instruction pointer is a repeated jmp back,
  # respectively the end of the loop.
  # @param ip [Integer] instruction pointer of examined pointer
  # @param loop_type [Symbol] :c_jmp or :unc_jmp, additional match, to be sure
  # it is relevant loop
  # @return [Integer] index of loop if matched, otherwise nil
  def is_end_of_loop?(ip, loop_type)
    @open_loops.each_with_index do |open_loop,i|
      return i if open_loop.is_end?(ip, loop_type)
    end
    return nil
  end

  # Add current instruction to all opened loops.
  # @param ins [Array] instruction
  def add_ins_to_open_loops(ins)
    @open_loops.each do |open_loop|
      open_loop.add_ins(ins)
    end
  end

  # Saves newly extracted loop.
  # @param l [Loop]
  def add_loop(l)
    if !l.tainted?
      $log.warn("Skipped non-tainted loop with start: #{l.start} and end: " +
                "#{l.end}.")
      return
    end
    if !l.tainted_targets.any?
      $log.warn("Skipped loop without targets with start: #{l.start} and end: " +
                "#{l.end}.")
      return
    end
    @loops << l
  end

  # Infer direction and target fields.
  # @param delimiters [Array] delimiters
  def infer_fields(delimiters)

    @dir_tar_fields = []
    $log.debug("Found #{@loops.count} tainted loops.")
    # Merge same/similar loops
    uniq_loops = []
    @loops.each do |l|
      if uniq_loops.empty?
        uniq_loops << [l]
        next
      end
      is_uniq = true
      uniq_loops.each do |ul|
        if ul.last == l
          ul << l
          is_uniq = false
          break
        end
      end
      uniq_loops << [l] if is_uniq
    end

    # Now traverse the loops and collect the final information.
    loop_results = []
    should_skip = false
    uniq_loops.each do |ul|
      direction_field = ul[0].get_direction_field
      tmp_dir_range = Range.new(direction_field.first, direction_field.last)
      target_fields = extract_targets(ul)
      target_fields.delete_if {|el| tmp_dir_range.include?(el) }
      # Compares used for delimiters, should not be used.
      filtered_targets = []
      delimiters.each do |del|
        del_size = del[0].length # delimiter itself
        del_pos = Range.new(del[1].last-del_size+1, del[1].last)
        if del_pos.include?(direction_field.first) ||
            del_pos.include?(direction_field.last)
          should_skip = true
          break
        else
          target_fields.each do |tf|
            # If one of the targets is within the delimiter, skip it
            if !del_pos.include?(tf)
              filtered_targets << tf
            else
            end
          end
        end
      end
      if !should_skip && target_fields.any?
        loop_results << [direction_field, filtered_targets.uniq]
      end
    end

    loop_results.uniq.each do |res|
      @dir_tar_fields << [res[0], res[1]] # compare / tainted loop head
    end

    $log.debug("OPEN_LOOPS: \n--|||--\n #{@open_loops.count}\n--|||--\n")
  end

  def get_fields
    raise "You have to call infer_fields first" if @dir_tar_fields.nil?
    return @dir_tar_fields
  end
  private
  # @!visibility private
  # Helper which extracts targets from the loops
  # @param uniq_loop [Array] interations of the same loop
  def extract_targets(uniq_loop)
    iterations = uniq_loop.count
    # A loop need at least two iterations or we discard it.
    return [] if iterations < 2
    addr_counter = {}
    uniq_loop.each do |l|
      ins_addrs = l.get_target_addrs
      ins_addrs.each do |addr|
        if addr_counter[addr].nil?
          addr_counter[addr] = 1
        else
          addr_counter[addr] += 1
        end
      end
    end

    relevant_addrs = []
    addr_counter.each_pair do |addr,count|
      relevant_addrs << addr if count == iterations # must in each loop
    end

    # Throw away instructions which touch the same data during every loop
    # iteration.
    non_uniq_targets = []
    relevant_addrs.each do |r_addr|
      targets = []
      uniq_loop.each do |l|
        targets << l.get_target_fields_by(r_addr)
      end
      old_count = targets.count
      targets.uniq! { |target| target.first && target.last }
      if old_count == targets.count
        targets.each { |t| non_uniq_targets += t }
      end
    end
    return non_uniq_targets
  end
end
