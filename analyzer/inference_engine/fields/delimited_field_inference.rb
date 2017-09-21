# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Responsible for infirence of demilters and delimited fields.
require_relative 'abstract_field_inference'
require_relative '../../utils/x86_reg'
include Inference
require_relative '../../utils/pin_iclass'
include Iclass::Inference
require_relative '../../utils/instruction_state'

class DelimitedFieldInference < AbstractFieldInference

  # Threshold as definde by polyglot paper. At least X bytes must be delimited.
  $DELIMITED_THRESHOLD = 3

  # Threshold as definde by polyglot paper. Max length of delimiter.
  $DELIMITER_LEN_THRESHOLD = 4

  # Constructor, initializes internal objects for all subclasses involved in the
  # inference step.
  def initialize
    # Delimiter Instructions (states), potentially used to determine delimited
    # fields.
    @delim_candidates = []

    # Final list with delimited fields.
    @delimited_fields = []

    # This variable is set after a cmp was found. Additionally, it is set only
    # when it didn't have the relevant flags from the next instruction.
    # When this is achieved it is set to nil again.
    @prev_r_a_v = nil


    # List of delimiters with an successful compare at the end. Only single byte
    # values. Items in this list were inside the possible_delimiters Hash and
    # moved to this hash if a successful cmp is found. A list of lists with the
    # format for each entry:
    #  [delimiter, [addr, cmp_flags]
    # (hashes) consiting of delimiter and an array of lists.
    @delimiters = []

    # Hash with possible extendable delimiter or part of keyword as key (one
    # byte), and an array of addresses value.
    # Later used either to extend existing delimiter or to assist in keyword
    # field inference.
    @successful_cmps = {}
  end

  # Add an tainted instruction which is relevant for inference of a delimited
  # field to the Delimiter Inference. If instruction not relevant then return
  # false. If the instruction/state was saved for processing return true.
  # @param is [InstructionState] current InstructionState object
  # @return [Array] cmp instruction, to be reused during direction inference
  def analyze_state(is)
    # If there was an relevant CMP before, then evaluate the flags were set by
    # it.
    if @prev_r_a_v
      # If an instruction before, there was a relevent CMP, then add flags to
      # it. The binary AND results in filtering the flags only a CMP sets.
      @prev_r_a_v << (is.regs['flags'] & 0b1_000_000)
      @delim_candidates << @prev_r_a_v
      $log.debug("Added following cmp to candidates: #{@prev_r_a_v.inspect}")
      @prev_r_a_v = nil
    end

    r_a_v = is.cmp_range_and_value
    if r_a_v
      @prev_r_a_v = r_a_v
      return r_a_v
    else
      return nil
    end
  end

  # Executes the actual analysis for delimiters and returns them.
  def infer_fields
    # Precheck, no analysis needed if trace has no results.
    if @delim_candidates.empty?
      @filtered_d_fields = []
      return
    end
    # This creates a token_table similar to the one in polyglot paper in section
    # 5.1.2 (1).
    @delim_candidates.sort! { |x,y| x[0] <=> y[0] }

    # Is made of an string as key which is either one or multiple chars long.
    # The value to the correspoinding key is an array with consecutive bytes,
    # belonging to the delimiter. If a possible delimiter is found or discarded,
    # then the key and its value is deleted from the hash.
    d_fields = []

    # Helper variable to hold the last delimiter added to possible_delimiters
    # hash.
    last_delim_candidate = []

    # Token list: tl = [addr, del_byte, cmp_flags]
    @delim_candidates.uniq.each do |tl|

      # Collect successful comparions for keyword inference.
      if tl[2] != 0
        if !@successful_cmps[tl[0]].nil? && @successful_cmps[tl[0]] != tl[1]
          $log.warn("There are two positive compares at the same address, but" +
                    " different values. This is strange. Could mean potential" +
                    " keyword field is incorrect. It is about addr: #{tl[0]} " +
                    "and the value #{@successful_cmps[tl[0]]} is overwritten " +
                    "by #{tl[1]}.")

        end
        @successful_cmps[tl[0]] = tl[1]
      end

      found_case = false
      d_fields.each do |d_field|
        last_tl = d_field.last

        # Consecutive address
        if tl[0] == (last_tl[0]+1)
          # Either delimiter found or it is a non successful cmp.
          if (tl[1] == last_tl[1]) && ((tl[2] == 0 && last_tl[2] == 0) ||
            (tl[2] != 0))
            d_field << tl
            found_case = true
            break
          elsif tl[2] != 0 && tl[1] != last_tl[1] # Delimiter extension to multi byte.
            last_d_byte = nil
            d_field.reverse.each do |d_byte|
              if !last_d_byte.nil?
                if d_byte[2] == 0 && last_d_byte[2] != 0 && d_byte[1] == last_d_byte[1]
                  d_field << tl
                  found_case = true
                  break
                end
              end
              last_d_byte = d_byte
            end # of d_field.reverse.each
          end # of if-elsif
        end # of if tl[0] == (last_tl[0]+1)
      end # of d_fields.each

      # Create a new possible delimiter since no positve
      d_fields << [tl] if !found_case
    end

    @filtered_d_fields = []
    @delimiter_addresses = []
    # Filter out cmps wich do not hold the following criateria
    # * length < $DELIMITED_THRESHOLD
    # * successful cmp at the end of the delimter scope.
    d_fields.each do |d_field|
      next if !within_threshold?(d_field) || d_field.last[2] == 0
      delimiter = []
      d_field.reverse_each do |el|
        if el[2] != 0
          delimiter << el[1]
          @delimiter_addresses << el[0]
        else
          break
        end
      end
      @filtered_d_fields << [delimiter.reverse, Range.new(d_field.first[0], d_field.last[0])]
    end
  end

  # Getter for the results.
  # @return [Array] Array with elements: [[delimiters], byte range]
  def get_fields
    raise "You have to call infer_fields first" if @filtered_d_fields.nil?
    return @filtered_d_fields
  end

  # Getter for successful compares saved during analysis. Is used as input for
  # keyword inference.
  # @return [Hash] contains addresses as key, value is compared byte.
  def get_successful_cmps
    raise "You have to call infer_fields first" if @filtered_d_fields.nil?
    return @successful_cmps
  end

  # Getter for the addreses of the successful compares saved during analysis.
  # Used during keyword inference to filter out keywords crossing delimiters.
  # @return [Array] addresses of delimiters
  def get_delimiter_addresses
    raise "You have to call infer_fields first" if @filtered_d_fields.nil?
    return @delimiter_addresses
  end

  private
  # @!visibility private
  # Helper to check whether at least $DELIMITED_THREESHOLD unsuccessful
  # comparisons were made and if not more the $DELIMITER_LEN_THRESHOLD of
  # successful compares were made.
  # @param d_field [Array] possible delimited and delimiter bytes
  # @return [Boolean] true when within the thresholds, otherweise false
  def within_threshold?(d_field)
    unsuc_count = 0
    suc_count = 0
    d_field.each do |d_byte|
      if d_byte[2] == 0
        unsuc_count += 1
      else
        suc_count += 1
      end
    end
    return false if unsuc_count < $DELIMITED_THRESHOLD
    if suc_count <= $DELIMITER_LEN_THRESHOLD && unsuc_count > 0
      return true
    else
      return false
    end
  end

end

