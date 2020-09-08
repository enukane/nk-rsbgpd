require "bgp4r"

neigh = BGP::Neighbor.new(:version => 4, :my_as => 65100, :remote_addr => "127.0.0.1", :id => "10.10.10.100", :hold_time => 20)

neigh.capability_mbgp_ipv4_unicast
neigh.capability_route_refresh
neigh.capability_route_refresh 128

neigh.start

loop do
  print "Enter subnet: "
  str = gets.strip
  if str == "close"
    "CLOSING connection"
    break;
  end
  puts "  updating #{str} network"
  an_update = BGP::Update.new(
    BGP::Path_attribute.new(
      BGP::Next_hop.new("10.10.10.100")
    ),
    BGP::Nlri.new(str)
  )
  neigh.send_message an_update
end
