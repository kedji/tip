#!/usr/bin/env ruby

# This is a demo program that parses Traffic Inspection Parcel (TIP) files and
# raises Hash objects on contained events.

class TIP

  def initialize(&cb)
    @made_by = nil
    @event_dict = {}
    @attr_dict = {}
    @callback = cb
    @stream = ""
  end

  attr_reader :callback, :made_by, :event_dict, :attr_dict
  attr_writer :callback

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
    event = { 'event_name' => event_id }

    # Now get the attribute values
    while data.length >= 7 and data.length - nbo(data[3, 4]) >= 7
      length = nbo(data[3, 4])
      attr_id = nbo(data[0, 2])
      attr_id = @attr_dict[attr_id] || attr_id
      attr_val = data[7, length]
      attr_val = nbo(attr_val) if data[2] == 0
      
      # Perform attribute value translation
      # ADD CODE HERE

      event[attr_id] = attr_val
      data[0, 7 + length] = ''
    end
    @callback.call(event) if @callback
  end

  def attribute_dictionary(value)
    while value.length >= 4 and value.length - nbo(value[2, 2]) >= 4
      @attr_dict[nbo(value[0, 2])] = value[4, nbo(value[2, 2])]
      value[0, 4 + nbo(value[2, 2])] = ''
    end
  end

  def event_dictionary(value)
    while value.length >= 4 and value.length - nbo(value[2, 2]) >= 4
      @event_dict[nbo(value[0, 2])] = value[4, nbo(value[2, 2])]
      value[0, 4 + nbo(value[2, 2])] = ''
    end
  end

end  # of class TIP


# Main program
if $0 == __FILE__
  tip_stream = TIP.new { |event| puts "#{event.inspect}\n\n" }
  ARGV.each { |f| tip_stream << File.read(f) }
end
