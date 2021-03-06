
# This class serializes and deserializes supported TIP attributes, including
# (potentially nested) containers (hashes and arrays) back and forth against
# their corresponding TIP parcels.

require 'ipaddr'

module TIP

  SUPPORTED_TYPES = [
    0x00, # an unsigned integer.
    0x01, # an unsigned integer representing a boolean value: 0 == false/no, 1 == true/yes
    0x02, # an unsigned integer representing an IPv4 address (ie, 0x01020304 == 1.2.3.4)
    0x03, # an unsigned integer representing the number of nanoseconds elapsed since the Unix epoch
    0x04, # a signed integer, first bit represents sign.
    0x05, # an unsigned integer code that can be converted into a string using the Attribute String Translator TIP.
    0x40, # a raw binary string.
    0x41, # a human-readable ascii string.
    0x42, # a 16-byte binary representation an IPv6 address (NBO).
    0x43, # an ascii string containing an error message.
    0x80, # a nested TIP list
    0x81, # a nested TIP hash
  ]

  # This function expects a TIP attribute string, which is a TLV in the form:
  #   +---- 1 ----+------ 4 ------+---- "length" ----+
  #   | attr type |  attr length  |   attr content   |
  #   +-----------+---------------+------------------+
  # If you want a method that's friendlier to parsing, call tip_to_attr_parse(),
  # which returns the entire TLV and accepts an offset into the given string.
  def TIP.tip_to_attr(str)
    t, l, v = tip_to_attr_parse(str, 0)
    v
  end

  # Same as the above method, but returns an array [ type, length, value ]
  # The returned length attribute describes the amount of data that can be
  # skipped to get to the next attribute.  You can also provide an offset into
  # the string where you'd like parsing to begin.
  def TIP.tip_to_attr_parse(str, offset = 0)
    attr_type = str[offset].ord
    length = str[offset + 1, 4].unpack("N").first
    raise "invalid TLV length" if str.length < length + 5 + offset
    raise "invalid TLV type" unless SUPPORTED_TYPES.include?(attr_type)
    value = str[offset + 5, length]
    value.force_encoding("BINARY") rescue nil
    case attr_type
      when 0x00
        value = ntoi(value)
      when 0x01
        value = (ntoi(value) > 0 ? true : false)
      when 0x02
        value = IPAddr.ntop(value)
      when 0x03
        value = Time.at(ntoi(value).to_f / 1000000000)
      when 0x04
        value = neg_ntoi(value)
      when 0x05
        value = ntoi(value)
      when 0x42
        value = IPAddr.ntop(value)
      when 0x43
        value = StandardError.new(value)
      when 0x80
        value = tip_to_array(value)
      when 0x81
        value = tip_to_hash(value)
    end
    [ attr_type, length + 5, value ]
  end

  # Convert a TIP list into a Ruby array
  def TIP.tip_to_array(str)
    ret = []
    pos = 4
    while pos < str.length do
      t, l, v = tip_to_attr_parse(str, pos)
      ret << v
      pos += l
    end
    ret
  end

  # Convert a TIP hash into a Ruby hash
  def TIP.tip_to_hash(str)
    ret = {}
    pos = 4
    while pos < str.length do
      t, l, key = tip_to_attr_parse(str, pos)
      pos += l
      t, l, value = tip_to_attr_parse(str, pos)
      pos += l
      ret[key] = value
    end
    ret
  end

  # Convert a Ruby object to a supported TIP attr type.  Will be returned as
  # a string in TLV format.
  def TIP.attr_to_tip(obj)
    attr_type = nil
    value = nil
    case obj
      when Integer          # positive and negative
        if obj >= 0
          value = iton(obj)
          attr_type = 0x00
        else
          value = neg_iton(obj)
          attr_type = 0x04
        end
      when TrueClass, FalseClass
        value = (obj ? "\x01" : "\x00")
        attr_type = 0x01
      when IPAddr           # IPv4 and IPv6
        value = obj.hton
        attr_type = (obj.ipv4? ? 0x02 : 0x42)
      when Time
        value = iton(obj.to_i * 1000000000 + obj.tv_nsec)
        attr_type = 0x03
      when String           # binary and human readable
        value = obj
        attr_type = 0x40
      when StandardError
        value = obj.to_s
        attr_type = 0x43
      when Array
        value = iton(obj.length, 4)
        obj.each { |x| value << attr_to_tip(x) }
        attr_type = 0x80
      when Hash
        value = iton(obj.length, 4)
        obj.each { |k,v| value << attr_to_tip(k) << attr_to_tip(v) }
        attr_type = 0x81
      else
        raise "Unsupported object type - #{obj.class}"
    end
    raise "attribute too large" if value.length >= 256**4
    attr_type.chr + iton(value.length, 4) + value
  end

  # Convert a string in Network Byte Order to an unsigned integer
  def TIP.ntoi(str)
    ret = 0
    str.each_byte { |byte| ret = (ret << 8) + byte }
    ret
  end

  # Convert a string in Network Byte Order to a signed integer where the first
  # bit represents sign.
  def TIP.neg_ntoi(str)
    return 0 if str.empty?
    neg = false
    ret = str[0].ord
    if ret >= 0x80
      ret -= 0x80
      neg = true
    end
    str[1..-1].each_byte { |byte| ret = (ret << 8) + byte }
    ret = 0 - ret if neg
    ret
  end

  # Convert an unsigned integer into the smallest possible ntoi string, or
  # one exactly the specified size.  The value of 0 will always take at least
  # one byte.
  def TIP.iton(num, bytes = 0)
    str = ''
    loop do
      str << (num & 0xFF).chr
      bytes -= 1
      num >>= 8
      break if num == 0 and bytes <= 0
    end
    str.reverse
  end

  # Convert an unsigned integer into the smallest possible NBO string with the
  # first bit representing sign.
  def TIP.neg_iton(num)
    str = iton(num.abs)
    str = "\x00" + str if str[0].ord >= 0x80
    str[0] = (str[0].ord | 0x80).chr if num < 0
    str
  end

end
