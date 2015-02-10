#!/usr/bin/perl -U -X
#
#    check_dhcp_relayed.pl
#    Copyright (C) 2012  Yavuz Selim Komur and Can Ugur Ayfer
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#
#############  IMPORTANT ################
# The -U param allows Perl to do unsafe 
# operations such as allowing to run SUID 
# programs. The script needs to be SUID 
# in order to broadcast/unicast on port 67, 68.
#
# The -X param supresses warnings. Warnings 
# confuse Nagios.
#
# Please note the security override and 
# use at your own risk.
#########################################

# check_dhcp_relayed.pl
#
# 27 Nov 2012

# A Perl script to be used as a Nagios check command.
# The script tests whether a DHCP server (localnet or 
# remote) can offer IP addresses.
#
# This script can be used to test whether a DHCP
# server can offer IP addresses to a specific subnet.
# 
# The script emulates a DHCP relay to check whether a
# remote DHCP server can talk DHCP to the Nagios Server.

# The DHCP server and the Nagios server NEED NOT both sit
# on the same network.

# Usage:
#    check_dhcp_relayed.pl -H  ip_addr
#                              IP addr for DHCP server (IP addr; not a Hostname.
#                              We won't try to resolve hostnames.)
#                          -m  mac_addr
#                              ":" separated Mac address to be used for the emulated client
#                              Default value : "99:mm:dd:hh:mm:ss" 
#                              where mm/dd/hh/mm/ss is the system date-time
#                          -n  network
#                              Emulated Network addr (the network address on which
#                              the emulated client is assumed to be sitting on).
#                              This option is especially convenient to check DHCP
#                              service on a specific subnet if you have a central
#                              DHCP server serving a bunch of disparate subnets.
#                              Make sure that this network is a REAL network and is
#                              served by the DHCP server.
#                              e.g. 139.179.123.0
#                          -N  netmask
#                              Netmask for the emulated network.
#                              e.g. 255.255.255.0
#                          -I  ip_addr
#                              IP addr expected to be offered by DHCP server
#                          -v  Be verbose... Useful for command line testing/debugging.
#                          -t  timeout in secs
#                              Note that the script will time out while waiting the server
#                              to make an offer when the address pool is exhausted.
#    e.g.
#        check_dhcp_relayed.pl -v
#                              -H 139.179.1.168 
#                              -m 12:22:33:44:55:66
#                              -n 139.179.123.0 
#                              -N 255.255.255.0 
#                              -I 139.179.123.234
#                              -t 10
#
#
# Installation: (Sorry! Installation notes are available only for Debian and derivatives. (Hi Ian!))
#
#               To Windows users: You should be using some flavor of Linux.
#
#               On the Nagios server:
#                   # apt-get install perl5 (probably you won't have to do this!)
#                   # cpan -i IO::Socket
#                   # apt-get install libgetopt-declare-perl (for Getopt::Std)
#                   # cpan -i Net::Address::IP::Local
#                   # apt-get install libnet-dhcp-perl  (for Net::DHCP)
#                   # apt-get install perl-suid         (for Perl to run SUID programs)
#
#                   1. Put this script in /usr/local/nagios/libexec (or where ever your check* commands live).
#                   2. render it executable ( chmod +x /usr/local/nagios/libexec/check_dhcp_relayed.pl )
#                   3. Make the script SUID:
#                         sudo chmod u+s /usr/local/nagios/libexec/check_dhcp_relayed.pl
#                   4. Make sure that the first line of the script matches the location of your Perl
#                      interpreter.

#
# Authors:	Yavuz Selim Komur (komur @t bilkent.edu.tr)
#               Can Ugur Ayfer (cayfer @t bilkent.edu.tr)



  use IO::Socket::INET;
  use IO::Socket 'sockatmark';
  use Net::DHCP::Packet;
  use Net::DHCP::Constants;
  use Net::Address::IP::Local;
  use Getopt::Std;

  # Parse the command line options
  
  $verbose = 0;

  $ip_addr = 0;
  getopts ("vH:m:n:N:I:t:");
  $dhcp_server = $opt_H if($opt_H);
  $netmask     = $opt_N if($opt_N);
  $network     = $opt_n if($opt_n);
  $ip_addr     = $opt_I if($opt_I);

  $timeout = 5;
  $timeout = $opt_t   if($opt_t);

  $verbose     = $opt_v;

  # calculate the default mac address
  # (generate a mac addr of the form "99:mm:dd:hh:mm:ss")

  ($sec,$min,$hour,$mday,$mon) = localtime(time);
  $mon  = sprintf("%02x",$mon);
  $mday = sprintf("%02x",$mday);
  $hour = sprintf("%02x",$hour);
  $min  = sprintf("%02x",$min);
  $sec  = sprintf("%02x",$sec);
  $mac = "99:".$mon.":".$mday.":".$hour.":".$min.":".$sec;

  $mac = $opt_m    if ($opt_m);  # if the user has specified a MAC addr, use it!

  $usage = "Usage:
            check_dhcp_relayed.pl [-v] -H <server_ip> -n <network> -N <netmask> [-m <mac_addr>] [-I <ip_addr>] [-t <secs>]";

  nagios_response (2, $usage) if (!$dhcp_server);
  nagios_response (2, $usage) if (!$netmask);
  nagios_response (2, $usage) if (!$network);

  $mac =~ s/://g;  # strip the mac address off any colons

  $my_ip = Net::Address::IP::Local->public_ipv4;  # who the hell am I

  # create a DHCP Packet
  $xid = int(rand(0x12345678));

  $discovery_connection = Net::DHCP::Packet->new(
                        Xid => $xid,                  # random xid
                        Flags => 0x8000,              # ask for broadcast answer
                        DHO_DHCP_MESSAGE_TYPE() => DHCPDISCOVER(),
			Giaddr => $my_ip,             # Client IP Addr
                        Chaddr => $mac,               # Client MAC Addr
                        );
  $discovery_connection->addOptionValue(DHO_SUBNET_SELECTION(), $network);
  $discovery_connection->addOptionValue(DHO_SUBNET_MASK(), $netmask);

  $out = $discovery_connection->toString();
  print_output ("Sending discovery message to $dhcp_server for network $network/$netmask using MAC: $mac...\n");

  # send DISCOVER packet
  $listen = IO::Socket::INET->new(Proto => 'udp',
                                  PeerPort => '67',
                                  LocalPort => '67',
                                  Timeout   => 10,
                                  PeerAddr => $dhcp_server)
                or die "socket: $@";     
  $handle = IO::Socket::INET->new(Proto => 'udp',
                                  PeerPort => '67',
                                  Timeout   => 10,
                                  LocalPort => '68',
                                  PeerAddr => $dhcp_server)
                or die "socket: $@";    
  $handle->send($discovery_connection->serialize())
                or die "Error sending broadcast message:$!\n";

  eval {   # We do not want to wait indefinitely till we get a response
        local $SIG{ALRM} = sub { die "Timed Out"; };
        alarm $timeout;
        $listen->recv($buf, 4096)|| die("Died when listening :$!");
        alarm 0;
  };
  alarm 0;
  if ($@ && $@ =~ /Timed Out/) {

     # Timeout can happen when:
     #   i) The server is unreachable
     #  ii) The server is out of addresses (address pool exhausted)
     # iii) The server is not a DHCP server.

     nagios_response (2, "CRITICAL: Timed out. Address pool exhausted or service unreachable!");
  }

  $response = new Net::DHCP::Packet($buf);
  $out = $response->toString();
  print_output ("Response to DISCOVER message received:\n");
  @lines =split(/\n/, $out);
  $ip_is_good = 0;
  foreach $line (@lines) {
      if ($line=~ /yiaddr =/) {
          print_output ("      ".$line."\n");
          # did we get a proper IP address offering?
          (undef, $offered_ip) = split('=', $line);
          if ($offered_ip=~ /\s*([0-9]{1,3}\.){3}[0-9]{1,3}\s*/) {
             $ip_is_good = 1;
             $offered_ip=~ s/^\s*//g;  # trim leading spaces
             $offered_ip=~ s/\s*$//g;  # trim trailing spaces
          }
       }
       print_output ("     ".$line."\n") if ($line=~ /DHO_DOMAIN_NAME_SERVERS/);
       print_output ("     ".$line."\n") if ($line=~ /DHO_ROUTERS/);
       print_output ("     ".$line."\n") if ($line=~ /DHO_SUBNET_MASK/);
       print_output ("     ".$line."\n") if ($line=~ /DHO_LEASE_TIME/);
   }
  
  if($ip_is_good) {
      if ($ip_addr) {
          if ($offered_ip eq $ip_addr) {
	      print_output ("  ".$ip_addr." matches offered\n");
              nagios_response(0,"OK");  # Offered IP matches expected IP
	  } else {
              nagios_response(2,"CRITICAL: incorrect DHCP-offered IP");
	  }
      } else {
          nagios_response(0,"OK");  # An offering is good enough for us. Means server is working
      }
  } else {
         nagios_response(2,"CRITICAL: Did not get a DHCP offer");
  } 

  exit;

  sub nagios_response {
     # $code is the program exit code so that Nagios knows whether the service is good or not
     # code:0 --> service is in good shape
     # code:1 --> warning (we don't use this)
     # code:2 --> CRITICAL error

     $code = shift;
     $msg  = shift;
     print "DHCP_RELAYED ".$msg."\n";
     exit($code);
  }

  sub print_output {
      return if (!$verbose);  # stay silent if not verbose 
      $msg = shift;
      print $msg;
      return;
  }
