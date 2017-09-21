# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Responsible for inference of direction and their target fields. This class
# infers pointer arithmetic direction/target fields.
require_relative 'abstract_field_inference'
require_relative '../../utils/pin_iclass'
include Iclass::Inference

class DirectionFieldInference < AbstractFieldInference

  # Constructor, initializes internal objects for all subclasses involved in the
  # inference step.
  def initialize
    @dir_field_candidates = []
    @dir_tar_fields = nil
  end

  def analyze_state(is)

    # Requirement for direction fields with pointer arithmetic.
    if multiple_mr?(is.iclass)
      unless (is.t_mr[0] || is.t_mr[1]) && (is.t_m_base.size >= 1 || is.t_m_index)
        return
      end
    else
      unless is.t_mr && (is.t_m_base || is.t_m_index)
        return
      end
    end

    if is.mr
      m_len = is.mr[1]
    else
      raise "Access length is zero. Not possible at this point!"
    end

    if is.t_m_base == is.t_m_index
      $log.warn("Base and index are the same. Hence, ignoring one of them.")
      t_m_index = nil
    end

    # First is target field range, second is access length, third is direction
    # address. If there is an index AND base register we build two
    # direction-target fields. We assume there are two direction fields with
    # same target field. If the base/index value is same as mr, then the
    # direction is not used as offset, skip it. Also the target must follow
    # the direction, not the other way around.
    if multiple_mr?(is.iclass)  # CMPsX have two mr and two base register
      if is.t_m_base[0] && is.t_m_base[0] < is.t_mr[0] && (is.t_m_base[0]+m_len) < is.t_mr[0]
        @dir_field_candidates << [is.t_mr[0], m_len, is.t_m_base[0]]
      end
      if is.t_m_base[1] && is.t_m_base[1] < is.t_mr[1] && (is.t_m_base[1]+m_len) < is.t_mr[1]
        @dir_field_candidates << [is.t_mr[1], m_len, is.t_m_base[1]]
      end
    else
      if is.t_m_base && is.t_m_base < is.t_mr && (is.t_m_base+m_len) < is.t_mr
        @dir_field_candidates << [is.t_mr, m_len, is.t_m_base]
      end
      if is.t_m_index && is.t_m_index < is.t_mr && (is.t_m_index+m_len) < is.t_mr
        @dir_field_candidates << [is.t_mr, m_len, is.t_m_index]
      end
    end
  end
  def infer_fields
    # Eliminate doubles. If a target has lower address, then use it instead of
    # the other. Described in
    # Polyglot 4.1.2 "Incrementing the pointer using arithmetic operations".
    uniq_dir_fields = []
    @dir_field_candidates.each do |df_candidate|
      found_double = false
      uniq_dir_fields.each do |uniq_f|
        if uniq_f[1] == df_candidate[1] && uniq_f[2] == df_candidate[2]
          found_double = true
          if uniq_f[2] < df_candidate[2]
            df_candidate[0] = uniq_f[0]
          end
          break
        end
      end
      # unique candidate or uniq_dir_fields is empty
      uniq_dir_fields << df_candidate if !found_double
    end

    @dir_tar_fields = []

    # Create full target address
    uniq_dir_fields.each do |df_candidate|
      target_end = df_candidate[0]-1
      access_len = df_candidate[1]
      if df_candidate[2]
        target = Range.new(df_candidate[2]+access_len, target_end).to_a
        direction = Range.new(df_candidate[2], df_candidate[2] + access_len-1).to_a
        @dir_tar_fields << [direction, target]
      end
    end
    @dir_tar_fields.uniq!
  end

  def get_fields
    raise "You have to call infer_fields first" if @dir_tar_fields.nil?
    return @dir_tar_fields
  end
end
