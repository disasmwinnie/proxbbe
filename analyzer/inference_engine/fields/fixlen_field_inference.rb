# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Responsible for infirence of fixed length fields.
require_relative 'abstract_field_inference'

class FixlenFieldInference < AbstractFieldInference
  # Constructor, initializes internal objects for all subclasses involved in the
  # inference step.
  def initialize
    @mem_accesses = []
    @fixlen_fields = nil
  end

  # Add an tainted instruction which is relevant for inference of a fixlen
  # fields to the FixlenFieldInference.
  # @param is [InstructionState] object of an instruction state
  def analyze_state(is)
    return if xfer?(is.iclass) || cond_xfer?(is.iclass)

    is.taint_labels.each do |t_label, access_size|
      target_range_array = Range.new(t_label, t_label+access_size-1).to_a
      @mem_accesses << target_range_array
    end
  end

  # Executes the actual analysis of collected data.
  def infer_fields(dirs_and_tars, counter_dirs_and_tars)
    @mem_accesses.uniq!

    filtered_mem_as = []
    @mem_accesses.each do |mem_a|
      is_uniq = true
      mem_a.each do |byte_pos|
        dirs_and_tars.each do |dat|
          if dat[0].include?(byte_pos) || dat[1].include?(byte_pos)
            is_uniq = false
            break
          end
        end
        counter_dirs_and_tars.each do |dat|
          if dat[0].include?(byte_pos) || dat[1].include?(byte_pos)
            is_uniq = false
            break
          end
        end
      end
      if is_uniq
        filtered_mem_as << mem_a
      else
        $log.warn("Filtered fixlen at #{mem_a.first} due existing direction.")
      end
    end

    # Now merge fields wich cross their boarders
    merged_fields = nil
    2.times do # doing two passes, helps to illuminates un-merged fields
      merged_fields = []
      filtered_mem_as.each do |mem_a|
        is_uniq = true
        merged = nil
        merged_fields.each_with_index do |mf,i|
          overall_len = mf.length + mem_a.length
          merged = (mem_a + mf).uniq
          if merged.length < (mf.length + mem_a.length)
            is_uniq = false
            $log.warn("Merged fixlen_fields at #{mf.first} and #{mem_a.first}")
            merged_fields[i] = merged.sort
          end
        end
        merged_fields << mem_a if is_uniq
      end
      filtered_mem_as = merged_fields
    end
    @mem_accesses = nil

    # Make 4-byte chunks
    chunked = []
    merged_fields.uniq.each do |f|
      chunked += f.each_slice(4).to_a
    end
    @fixlen_fields = []
    chunked.uniq.each do |f|
      @fixlen_fields << Range.new(f.first, f.last)
    end
  end

  # Getter for the results.
  # @return [Array] Array with ranges of fixlen fields, whereas one range
  # represents one fixlen field
  def get_fields
    raise "You have to call infer_fields first" if @fixlen_fields.nil?
    return @fixlen_fields
  end

end
