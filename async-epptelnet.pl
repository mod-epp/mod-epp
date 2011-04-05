#!/usr/bin/perl -w
#
# Simple EPP/TCP client to talk to an EPP server using the EPP over TCP layer
#
# Basically, this program prefixes each data block with a 4-byte prefix.
# Input blocks are terminated by a double newline.
#
# Written by Otmar Lendl <lendl@nic.at>

use Socket;
use strict;
use Getopt::Long;

$| = 1;  # no buffering, please

sub usage
{
print STDERR <<EOM;
Usage:

	$0 host port

Connect via TCP to the specified host an port. 
Wait for a complete paragraph of text on STDIN, then send it
as an EPP/TCP frame to the host.

Remarks:
	This is the async implementation. Input and output side do not wait 
	for each other.

/ol/2011/04/01/
EOM

exit 0;
}

&usage if ($#ARGV != 1);

my $host = shift;
my $port = shift;


# input by paragraph.

$/ = "\n\n";


my $ip = gethostbyname($host);
my $host_params = sockaddr_in($port,$ip);

socket(S, &AF_INET, &SOCK_STREAM, 0) or die "socket: $!";
connect(S, $host_params) or die "connect: $!";
select(S); $| = 1; select (STDOUT);

print STDERR "Connected.\n";

	
my $len;
my $header;
my $in;
my $pid;
if ($pid = fork()) {
	# Parent: communication towards to server
	while(1) {
		
		# get input from user;
		last unless defined($_ = <>);

		$len = length($_) + 4;
		print STDERR "got input: $len bytes.\n";
		$header = pack("N",$len);

		print S $header, $_;

		print STDERR "Sent $len bytes.\n";
	}
	wait();
} else{ # CHILD
	while(1) {
		#
		# read the frame
		#
		if (sysread(S,$header,4) != 4) { die "Can't read EPP/TCP header.";} 

		$len = unpack("N",$header) - 4;

		print STDERR "EPP/TCP Header: expecting $len bytes of XML\n";

		while($len > 0) {
			$len -= sysread(S,$in,4096);
			print $in;
		}
	}
	exit;
}


close S;
