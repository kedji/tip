#!/usr/bin/env ruby

# Test hack to make a fake .TIP file

# convert an integer to a Network Byte Order string of the given length
def nbo(val, width)
  ret = ''
  width.times { ret = (val % 256).chr + ret ; val >>= 8 }
  ret
end

# create a fake event attribute
def attr(id, val)
  type = nbo(1, 2)
  if val.class <= Integer
    type = nbo(0, 2)
    val = nbo(val, 8)
  end
  "#{nbo(id, 2)}#{type}#{nbo(val.length, 4)}#{val}"
end

# create a fake event/attribute dictionary entry
def dict_entry(id, name)
  "#{nbo(id, 2)}#{nbo(name.length, 2)}#{name}"
end

# create a parcel of the given data and type
def parcel(type, payload)
  "#{(type / 256).chr}#{(type % 256).chr}#{nbo(payload.length, 6)}#{payload}"
end

File.open('fake.tip', 'w') do |fake|
  fake.print parcel(0x1a01, "fake_tip.rb")

  # Make a fake event dictionary
  dict =  dict_entry(1, "flow_start")
  dict << dict_entry(2, "malicious_thing_happened")
  dict << dict_entry(3, "flow_end")
  fake.print parcel(0x1aed, dict)

  # Make a fake attribute dictionary
  dict =  dict_entry(1, 'client_ip')
  dict << dict_entry(2, 'server_ip')
  dict << dict_entry(3, 'server_port')
  dict << dict_entry(4, 'cause')
  fake.print parcel(0x1aad, dict)

  # Make a fake start event
  base_event =  attr(1, '10.0.0.5')
  base_event << attr(2, '10.0.0.121')
  base_event << attr(3, 80)
  fake.print parcel(0x1ace, nbo(1, 2) + base_event)

  # Make a fake happenstance event
  event = base_event.dup
  event << attr(4, 'human-readable protocol was used')
  event << attr(5, 'this attribute has no dictionary entry')
  fake.print parcel(0x1ace, nbo(2, 2) + event)

  # Make a fake end event
  fake.print parcel(0x1ace, nbo(3, 2) + base_event)
end
