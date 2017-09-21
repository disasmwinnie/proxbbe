# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)

require_relative '../utils/buffered_reading_oracle'
include BufferedReadingOracle
include BufferedReadingOracle::ACTION

# The resulting protocol model, which conflates all inferred fields together.
# The final protocol model can only be created when looking at all packets at
# the same time, since some field inference phases don't deliver conclusive
# results on their own.
class ProtocolModel
  attr_reader :text_model

  def initialize(packets, delimiters, keywords, dirs_and_tars,
                 dirs_and_tars_counter, fixlens)
    @packets = packets
    @delimiters = delimiters
    @keywords = keywords
    @dirs_and_tars = dirs_and_tars
    @dirs_and_tars_counter = dirs_and_tars_counter
    @fixlens = fixlens
    build_model
  end

  # conflate
  def build_model
    models = []
    @packets.each do |p|
      proto_model = Array.new(p[:count])
      offset = p[:buf_addr]
      # DELIMITER
      @delimiters.each do |d|
        d_alias_t = gen_del_alias() # pseudo name for delimited fields
        d_alias = d_alias_t.capitalize # pseudo name for alias

        del_size = d[0].length # delimiter itslef
        field_start = d[1].first-offset # first field index
        field_end = d[1].last-offset # last field index
        new_range = Range.new(field_start, field_end)
        delimiter_positions = Range.new(new_range.last-del_size+1, new_range.last)

        begin
          raise if field_end > proto_model.size
          new_range.each do |i|
            # delimiter or delimted field?
            filler = delimiter_positions.include?(i) ? d_alias : d_alias_t

            if proto_model[i].nil?
              proto_model[i] = [filler]
            else # multiple delimter scopes
              proto_model[i][0] += '|' + filler
            end
          end
        rescue
          $log.debug("Skipped delimiter: #{d}. Doesn't match to this packet.")
        end
      end
      # DELIMITER
      proto_model.each_with_index { |e,i| proto_model[i] = [''] if e.nil? }
      # KEYWORDS
      @keywords.each do |k|
        field_start = k[1].first-offset # first field index
        field_end = k[1].last-offset # last field index
        new_range = Range.new(field_start, field_end)
        k_alias = gen_key_alias()
        begin
          raise if field_end > proto_model.size
          new_range.each do |i|
            if proto_model[i].length == 1
              proto_model[i] << k_alias
            elsif proto_model[i].length == 2
              proto_model[i][1] += '|' + k_alias
            end
          end
        rescue
          $log.debug("Skipped keyword: #{k}. Doesn't match to this packet.")
        end
      end
      # KEYWORDS
      proto_model.each_with_index { |e,i| proto_model[i] << '' if e.length == 1 }
      # DIRECTION-TARGETS
      @dirs_and_tars.each do |dat|
        direction_alias = gen_direction_alias()
        target_alias = gen_target_alias()
        dir_field_start = dat[0].first-offset # first field index
        dir_field_end = dat[0].last-offset # last field index
        dir_new_range = Range.new(dir_field_start, dir_field_end)
        begin
          raise if dir_field_end > proto_model.size
          dir_new_range.each do |i|
            if proto_model[i].length == 2  # delimiter and keyword
              proto_model[i][2] = direction_alias
            elsif proto_model[i].length == 3  # There's already a direction
              proto_model[i][2] += '|' + direction_alias
            end
          end
        rescue
          $log.debug("Skipped direction: #{dat[0]}. Doesn't match this packet.")
          next
        end
        begin
          tar_field_start = dat[1].first-offset # first field index
          tar_field_end = dat[1].last-offset # last field index
          raise if tar_field_end > proto_model.size
          tar_new_range = Range.new(tar_field_start, tar_field_end)
          tar_new_range.each do |i|
            if proto_model[i].length == 2  # delimiter and keyword
              proto_model[i][2] = target_alias
            elsif proto_model[i].length == 3  # There's already a direction
              proto_model[i][2] += '|' + target_alias
            end
          end
        rescue
          # Rollback direction fields if any.
          dir_new_range.each do |i|
            if proto_model[i][2].include?('|')
              last_pipe = proto_model[i][2].reverse.index('|') + 1 # include the pipe
              last_pipe *= -1
              del_str = proto_model[i][2][last_pipe..-1]
              proto_model[i][2].slice!(del_str)
              $log.debug("Deleted: #{del_str} from #{proto_model[i][2]} " +
                         "due rollback")
            else
              $log.debug("Deleted: #{proto_model[i][2]} from #{proto_model[i][2]} " +
                         "due rollback")
              proto_model[i].delete_at(2)[2] = ''
            end
          end
          $log.debug("Skipped target: #{dat[1]}. Doesn't match this packet.")
        end
        tar_field_start = dat[1].first-offset # first field index
        tar_field_end = dat[1].last-offset # last field index
        tar_new_range = Range.new(tar_field_start, tar_field_end)
      end
      # DIRECTION-TARGETS
      proto_model.each_with_index { |e,i| proto_model[i] << '' if e.length == 2 }
      # COUNTER DIRECTION-TARGETS
      @dirs_and_tars_counter.each do |dat|
        c_direction_alias  = gen_counter_direction_alias()
        c_target_alias = gen_counter_target_alias()
        c_dir_field_start = dat[0].first-offset # first field index
        c_dir_field_end = dat[0].last-offset # last field index
        c_dir_new_range = Range.new(c_dir_field_start, c_dir_field_end)
        begin
          raise if c_dir_field_end > proto_model.size
          c_dir_new_range.each do |i|
            if proto_model[i].length == 3
              proto_model[i][3] = c_direction_alias
            elsif proto_model[i].length == 4  # There's already a direction
              proto_model[i][3] += '|' + c_direction_alias
            end
          end
        rescue
          $log.debug("Skipped counter-direction: #{dat[0]}. Doesn't match " +
                     "this packet.")
          next
        end
        dat[1].each do |i|
          i -= offset
          next if i > proto_model.size-1 || i < 0
          if proto_model[i].length == 3
            proto_model[i][3] = c_target_alias
          elsif proto_model[i].length == 4  # There's already a direction
            proto_model[i][3] += '|' + c_target_alias
          end
        end

      end
      # COUNTER DIRECTION-TARGETS
      proto_model.each_with_index { |e,i| proto_model[i] << '' if e.length == 3 }
      # FIXED_LENGTH
      @fixlens.each do |fl|
        fl_alias = gen_fixlen_alias()
        fl_start = fl.first-offset # first field index
        fl_end  = fl.end-offset   # last field index
        fl_new_range = Range.new(fl_start, fl_end)
        begin
          raise if fl_end > proto_model.size
          fl_new_range.each do |i|
            if proto_model[i].length == 4
              proto_model[i][4] = fl_alias
            elsif proto_model[i].length == 5  # There's already a direction
              proto_model[i][4] += '|' + fl_alias
            end
          end
        rescue
          $log.debug("Skipped fixed length field: #{fl}. Doesn't match this " +
                     "packet")
        end
      end
      # FIXED_LENGTH
      proto_model.each_with_index { |e,i| proto_model[i] << '' if e.length == 4 }
      models << [proto_model, p[:msg]]
    end
    if models.length == 1
      draw(models[0][0], models[0][1])
      return
    end
    # merge packet results
    current_model = models[0]
    biggest_model = models[0][0].length
    last_flags = @packets[0][:action]
    models.each_with_index do |m,i|
      next if i == 0
      if last_flags == ACTION::PEEK # MSG_PEEK, merge results
        last_flags = @packets[i][:action]
        if @packets[i][:buf_addr] != @packets[i-1][:buf_addr]
          $log.warn("Cant't merge MSG_PEEK packet since different buffers " +
                    "were used. I am appending it to previous message instead.")
          append_packet(current_model, m, @packets[i-1], @packets[i])
        elsif biggest_model < models[i][0].length
          biggest_model = models[i][0].length
          current_model = merge_packets(m, current_model, @packets[i],
                                        @packets[i-1])
        else
          current_model = merge_packets(current_model, m, @packets[i-1],
                                        @packets[i])
        end
      else # continuing packet, append
        append_packet(current_model, m, @packets[i-1], @packets[i])
      end
    end
    draw(current_model[0], current_model[1])
  end

  # Bigger model and packet passed first as p1 respectively m1.
  def merge_packets(m1, m2, p1, p2)
    m1[0].zip(m2[0]).each_with_index do |m,i_m1|
      break if m[1].nil?

      m1[0][0].zip(m[1]).each_with_index do |f,i|
        next if f[0].nil? || f[1].nil? # skip if one of the fields has no more results
        # zip creates a new array, so we have to change pointers in the model itself
        m1[0][i_m1][i] += '|' + f[1]
      end
    end
    return m1
  end

  def append_packet(current_m, m, current_p, p)
    current_m[0] << m[0]
    current_m[1] << m[1]
    return current_m
  end

  # Getter for delimiter aliases..
  def gen_del_alias
    @del_count ||= 0
    del_index = @del_count.to_s
    @del_count += 1
    return ("d" + del_index)
  end

  def gen_key_alias
    @key_count ||= 0
    key_index = @key_count.to_s
    @key_count += 1
    return ("K" + key_index)
  end

  def gen_direction_alias
    @direction_count ||= 0
    dat_index = @direction_count.to_s
    @direction_count += 1
    return ("DI" + dat_index)
  end

  def gen_counter_direction_alias
    @c_direction_count ||= 0
    c_dat_index = @c_direction_count.to_s
    @c_direction_count += 1
    return ("CO" + c_dat_index)
  end

  def gen_counter_target_alias
    @c_target_count ||= 0
    c_tar_index = @c_target_count.to_s
    @c_target_count += 1
    return ("TC" + c_tar_index)
  end

  def gen_target_alias
    @target_count ||= 0
    target_index = @target_count.to_s
    @target_count += 1
    return ("TA" + target_index)
  end

  def gen_fixlen_alias
    @fixlen_count ||= 0
    fixlen_index = @fixlen_count.to_s
    @fixlen_count += 1
    return ("FX" + fixlen_index)
  end

  def draw(model_array, msg_data)
    output_line = "Protocol Model: \n\n"
    text_line = ''
    str_line = nil
    model_array.each_with_index do |byte,i|
      str_line = "%3s |" % i.to_s
      output_line << str_line
      text_line << str_line
      str_line  = "%4s   " %  convstr(msg_data[i])
      str_line  << "%4s\t" %  convstr_hex(msg_data[i])
      text_line << str_line
      output_line << white_bg(black(str_line))
      #print(output_line)
      # delimiter start
      if model_array[i].nil? || model_array[i][0] == ''
        str_line = "          \t"
      else
        str_line = "%10s\t" %  model_array[i][0]
      end
      text_line << str_line
      output_line << black_bg(red(str_line)) + '|'
      # delimiter end
      # keyword start
      if model_array[i].nil? || model_array[i][1].nil?
        str_line = "          \t"
      else
        str_line = "%10s\t" %  model_array[i][1]
      end
      text_line << str_line
      output_line << black_bg(green(str_line)) + '|'
      # keyword end
      # direction_target start
      if model_array[i].nil? || model_array[i][2].nil?
        str_line = "          \t"
      else
        str_line = "%10s\t" %  model_array[i][2]
      end
      text_line << str_line
      output_line << black_bg(yellow(str_line)) + '|'
      # direction_target end
      # counter direction start
      if model_array[i].nil? || model_array[i][3].nil?
        str_line = "          \t"
      else
        str_line = "%10s\t" %  model_array[i][3]
      end
      text_line << str_line
      output_line << black_bg(cyan(str_line)) + '|'
      # counter direction end
      # fixed lenght start
      if model_array[i].nil? || model_array[i][4].nil?
        str_line = "          \t"
      else
        str_line = "%10s\t" %  model_array[i][4]
      end
      text_line << str_line
      output_line << black_bg(magenta(str_line)) + '|'
      # fixed lenght end
      str_line = "\n" + '_'*120 + "\n"
      output_line << str_line
      text_line << str_line
    end
    output_line << "\nProtocol Model ouput finished\n"
    @text_model = text_line
    puts(output_line)
  end
  ####### RIDE THE RAINBOW
  def colorize(text, color_code)
    "#{color_code}#{text}\e[0m"
  end
  def black(text); colorize(text, "\e[30m"); end
  def red(text); colorize(text, "\e[31m"); end
  def green(text); colorize(text, "\e[32m"); end
  def yellow(text); colorize(text, "\e[33m"); end
  def magenta(text); colorize(text, "\e[35m"); end
  def cyan(text); colorize(text, "\e[36m"); end
  def black_bg(text); colorize(text, "\x1b[40m"); end
  def white_bg(text); colorize(text, "\x1b[47m"); end
  ####### RIDE THE RAINBOW

  # String converter for mixed printable and non-printable character strings.
  def convstr(str)
    return '.' if str.nil?
    new_str = ''
    str.each_byte do |b|
      if (b < 128 && b > 31)
        new_str << b.chr
      elsif b == 10
        new_str << '\n'
      elsif b == 13
        new_str << '\r'
      elsif b == 0
        new_str << '\0'
      else
        new_str << '.'
      end
    end
    return new_str
  end
  def convstr_hex(str)
    new_str = ''
    str.each_byte do |b|
      new_str << sprintf('\x%02x', b)
    end
    return new_str
  end

end
