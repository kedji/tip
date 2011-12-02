#!/usr/bin/env ruby

# This application provides full TIP parsing and serialization functionality.

require 'ipaddr'

class TIP

  def initialize()
    @made_by = nil
    @event_dict = {}
    @attr_dict = {}
    @attr_characteristics = {}
    @attr_translations = {}
    @event_structures = []
    @array_elements = []
    @callback = nil
    @stream = ""
  end

  attr_reader :callback, :made_by, :event_dict, :attr_dict, :verbose
  attr_writer :callback, :verbose

  # Convert a string in Network Byte Order to an unsigned integer
  def ntoi(str)
    ret = 0
    str.each_byte { |byte| ret = (ret << 8) + byte }
    ret
  end

  # Convert an unsigned integer into the smallest possible ntoi string, or
  # one exactly the specified size.  The value of 0 will always take at least
  # one byte.
  def iton(num, bytes = 0)
    str = ''
    loop do
      str << (num & 0xFF).chr
      bytes -= 1
      num >>= 8
      break if num == 0 or bytes == 0
    end
  end

  # Push TIP stream data here, the callback function will get called on
  # each complete Content Event parcel.  Raises an exception on broken parcels.
  def <<(parcel_data)
    @stream << parcel_data

    # Loop through as many complete parcels as we have
    while @stream.length >= 6 and @stream.length - ntoi(@stream[2, 4]) >= 8
      type = ntoi(@stream[0, 2])
      length = ntoi(@stream[2, 4])
      value = @stream[6, length]
      @stream[0, 6 + length] = ''

      case type
        when 0x1A01
          made_by_version(value)
        when 0x1ACE
          content_event(value)
        when 0x1AAD
          attribute_dictionary(value)
        when 0x1AED
          event_dictionary(value)
        when 0x1AAC
          attribute_characteristics(value)
        when 0x1AA5
          attribute_translator(value)
        when 0x1AE5
          event_structures(value)
        else
          puts "Unknown parcel type: 0x#{'%04x' % type}"
      end
    end
  end

  def made_by_version(data)
    @made_by = data
  end

  def content_event(data)
    event_id = ntoi(data[0, 2])
    
    # Get the event name if possible, otherwise just use the numeric id
    event_name = @event_dict[event_id] || event_id.to_s
    data[0, 2] = ''
    event = { 'event_name' => event_name }
    event = new_event_object(event_id)

    # Now get the attribute values
    while data.length >= 7 and data.length - ntoi(data[3, 4]) >= 7
      length = ntoi(data[3, 4])
      attr_id = ntoi(data[0, 2])
      attr_name = (@attr_dict[attr_id] || attr_id).to_s.to_sym
      attr_val = data[7, length]
      attr_type = data[2].ord

      # Convert the attribute based on its type
      case attr_type
        when 0
          attr_val = ntoi(attr_val)
        when 1
          attr_val = [ false, true ][ntoi(attr_val)]
        when 2
          attr_val = IPAddr.new(ntoi(attr_val), 2)
        when 3
          attr_val = Time.at(ntoi(attr_val))
        when 4
          attr_val = ntoi(attr_val)
          # ADD CODE HERE
        when 5
          # Remember, not all "code" objects have attr translation entries
          if (@attr_translations[attr_id])
            attr_val = @attr_translations[attr_id][ntoi(attr_val)] ||
                       ntoi(attr_val)
          else
            attr_val = ntoi(attr_val)
          end
        when 33
          attr_val = IPAddr.new(attr_val, 10)
      end
      
      # Perform attribute value translation
      if @attr_characteristics[attr_id] and
         @attr_characteristics[attr_id].include?(:annotation)
        attr_val = [ attr_name, attr_val ]
        attr_name = :annotation
      end

      if event[attr_name].class <= Array
        event[attr_name] << attr_val
      else
        event[attr_name] = attr_val
      end
      data[0, 7 + length] = ''
    end
    @callback.call(event) if @callback
  end

  def attribute_dictionary(value)
    while value.length >= 4 and value.length - ntoi(value[2, 2]) >= 4
      @attr_dict[ntoi(value[0, 2])] = value[4, ntoi(value[2, 2])]
      value[0, 4 + ntoi(value[2, 2])] = ''
    end
    if @verbose
      puts "\n-- Attribute Dictionary: --"
      @attr_dict.to_a.sort.each { |k,v| puts("%5d => %s" % [ k, v ]) }
    end
  end

  def event_dictionary(value)
    while value.length >= 4 and value.length - ntoi(value[2, 2]) >= 4
      @event_dict[ntoi(value[0, 2])] = value[4, ntoi(value[2, 2])]
      value[0, 4 + ntoi(value[2, 2])] = ''
    end
    if @verbose
      puts "\n-- Event Dictionary: --"
      @event_dict.to_a.sort.each { |k,v| puts("%5d => %s" % [ k, v ]) }
    end
  end

  def attribute_characteristics(value)
    while value.length >= 6
      attr_id = ntoi(value[0, 2])
      attr_chars = ntoi(value[2, 4])
      value[0, 6] = ''
      @attr_characteristics[attr_id] = characteristic_deflag(attr_chars)
    end
    if @verbose
      puts "\n-- Attribute Characteristics --"
      @attr_characteristics.to_a.sort.each do |id,char_list|
        nid = @attr_dict[id] || ("%3d" % id)
        puts("  (#{id}) #{nid} => #{char_list.inspect}")
      end
    end
  end

  def attribute_translator(value)
    attr_id = ntoi(value[0, 2])
    value[0, 2] = ''
    trans_hash = {}
    while value.length > 6 and ntoi(value[4, 2]) + 6 <= value.length
      attr_value = ntoi(value[0, 4])
      attr_string = value[6, ntoi(value[4, 2])]
      value[0, 6 + attr_string.length] = ''
      trans_hash[attr_value] = attr_string
    end
    @attr_translations[attr_id] = trans_hash
    if @verbose
      puts "\n-- Attribute Translation --"
      id = @attr_dict[attr_id] || ("%3d" % attr_id)
      puts("#{id}: #{trans_hash.inspect}")        
    end
  end

  # Event structure depends on the event and attribute dictionaries
  def event_structures(value)
    event_ids = []
    while value.length > 4 and value.length >= 4 + ntoi(value[2,2])
      event_id = ntoi(value[0, 2])
      event_ids << event_id
      e_struct = [ :event_name, :annotation ]
      multi = [ :annotation ]
      (ntoi(value[2, 2]) / 4).times do |i|
        attr_name = @attr_dict[ntoi(value[4 * i + 4, 2])]
        e_struct << attr_name.to_sym
        multi << attr_name.to_sym if ntoi(value[4 * i + 6, 1]) == 2
      end
      @event_structures[event_id] = Struct.new(*e_struct)
      @array_elements[event_id] = multi
      value[0, ntoi(value[2, 2]) + 4] = ''
    end
    if @verbose
      puts "\n-- Event Structures --"
      event_ids.each do |event_id|
        obj = new_event_object(event_id)
        puts "  #{@event_dict[event_id]}:"
        obj.each_pair { |k,v| puts "    #{k} #{"=> #{v.inspect}" if v}" }
        puts "\n"
      end
    end
  end

  def characteristic_deflag(flags)
    ret = []
    ret << :annotation if flags & 0x0001 > 0
    ret << :string     if flags & 0x0002 > 0
    ret << :ip         if flags & 0x0004 > 0
    ret
  end

  # Generate an event object of the type identified by its id
  def new_event_object(event_id)
    ret = @event_structures[event_id].new
    @array_elements[event_id].each { |elem| ret[elem] = [] }
    ret.event_name = event_dict[event_id]
    ret
  end

end  # of class TIP


# Main program
if $0 == __FILE__
  tip_stream = TIP.new
  tip_stream.callback = Proc.new { |event| puts "#{event.inspect}\n\n" }
  if ARGV.empty?
    puts "Usage: #{$0} <tip> [tip...]"
    Kernel.exit(1)
  end
  ARGV.each do |f|
    if f == '-v'
      tip_stream.verbose = true
    else
      tip_stream << File.read(f)
    end
  end
end
