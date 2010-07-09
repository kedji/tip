#!/usr/bin/env ruby

# This is a demo program that parses Traffic Inspection Parcel (TIP) files and
# raises Hash objects on contained events.

class TIP

  def initialize(&cb)
    @made_by = nil
    @event_dict = {}
    @attr_dict = {}
    @attr_characteristics = {}
    @attr_translations = {}
    @callback = cb
    @stream = ""
    @verbose = false
  end

  attr_reader :callback, :made_by, :event_dict, :attr_dict, :verbose
  attr_writer :callback, :verbose

  # Convert a string in Network Byte Order to an unsigned integer
  def nbo(str)
    ret = 0
    str.each_byte { |byte| ret = (ret << 8) + byte }
    ret
  end

  # Push TIP stream data here, the callback function will get called on
  # each complete Content Event parcel.  Raises an exception on broken parcels.
  def <<(parcel_data)
    @stream << parcel_data

    # Loop through as many complete parcels as we have
    while @stream.length >= 8 and @stream.length - nbo(@stream[2, 6]) >= 8
      type = nbo(@stream[0, 2])
      length = nbo(@stream[2, 6])
      value = @stream[8, length]
      @stream[0, 8 + length] = ''

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
    event_id = nbo(data[0, 2])

    # Get the event name if possible, otherwise just use the numeric id
    event_id = @event_dict[event_id] || event_id
    data[0, 2] = ''
    event = { 'event_id' => event_id }

    # Now get the attribute values
    while data.length >= 8 and data.length - nbo(data[4, 4]) >= 8
      length = nbo(data[4, 4])
      attr_id = nbo(data[0, 2])
      attr_id = @attr_dict[attr_id] || attr_id
      attr_val = data[8, length]
      attr_val = nbo(attr_val) if data[3] == 0
      
      # Perform attribute value translation
      # ADD CODE HERE

      event[attr_id] = attr_val
      data[0, 8 + length] = ''
    end
    @callback.call(event) if @callback
  end

  def attribute_dictionary(value)
    while value.length >= 4 and value.length - nbo(value[2, 2]) >= 4
      @attr_dict[nbo(value[0, 2])] = value[4, nbo(value[2, 2])]
      value[0, 4 + nbo(value[2, 2])] = ''
    end
    if @verbose
      puts "\n-- Attribute Dictionary: --"
      @attr_dict.to_a.sort.each { |k,v| puts("%5d => %s" % [ k, v ]) }
    end
  end

  def event_dictionary(value)
    while value.length >= 4 and value.length - nbo(value[2, 2]) >= 4
      @event_dict[nbo(value[0, 2])] = value[4, nbo(value[2, 2])]
      value[0, 4 + nbo(value[2, 2])] = ''
    end
    if @verbose
      puts "\n-- Event Dictionary: --"
      @event_dict.to_a.sort.each { |k,v| puts("%5d => %s" % [ k, v ]) }
    end
  end

  def attribute_characteristics(value)
    while value.length >= 6
      attr_id = nbo(value[0, 2])
      attr_chars = nbo(value[2, 4])
      value[0, 6] = ''
      @attr_characteristics[attr_id] = characteristic_deflag(attr_chars)
    end
    if @verbose
      puts "\n-- Attribute Characteristics --"
      @attr_characteristics.to_a.sort.each do |id,char_list|
        id = @attr_dict[id] || ("%3d" % id)
        puts("  #{id} => #{char_list.inspect}")
      end
    end
  end

  def attribute_translator(value)
    attr_id = nbo(value[0, 2])
    value[0, 2] = ''
    trans_hash = {}
    while value.length > 6 and nbo(value[4, 2]) + 6 <= value.length
      attr_value = nbo(value[0, 4])
      attr_string = value[6, nbo(value[4, 2])]
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

  def event_structures(value)
    puts "event_structures"
  end

  def characteristic_deflag(flags)
    ret = []
    ret << :annotation if flags & 0x0001 > 0
    ret << :signed     if flags & 0x0002 > 0
    ret << :boolean    if flags & 0x0004 > 0
    ret << :string     if flags & 0x0008 > 0
    ret << :ip         if flags & 0x0010 > 0
    ret << :time       if flags & 0x0020 > 0
    ret
  end

end  # of class TIP


# Main program
if $0 == __FILE__
  tip_stream = TIP.new { |event| puts "#{event.inspect}\n\n" }
  ARGV.each do |f|
    if f == '-v'
      tip_stream.verbose = true
    else
      tip_stream << File.read(f)
    end
  end
end
