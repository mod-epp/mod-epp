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


my ($opt_d, $opt_2);

GetOptions("delay|d", \$opt_d, "duplicate|2", \$opt_2);

sub usage
{
print STDERR <<EOM;
Usage:

	$0 [-2] [-d] host port

Connect via TCP to the specified host an port. 
Wait for a complete paragraph of text on STDIN, then send it
as an EPP/TCP frame to the host.

Options:
	-2	Duplicate each message without waiting for an answer
	-d	delay sending.

This is a simple half-duplex implementation.

EOM

exit 0;
}

&usage if ($#ARGV != 1);

my $host = shift;
my $port = shift;

&usage if ($host !~ /^[\a-z0-9-.]+$/);
&usage if ($port !~ /^\d+$/);

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

#
# read the greeting
#
if (sysread(S,$header,4) != 4) { die "Can't read EPP/TCP header.";}
$len = unpack("N",$header) - 4;

print STDERR "EPP/TCP Header: expecting $len bytes of XML\n";

while($len > 0)
	{
	$len -= sysread(S,$in,4096);
	print $in;
	}
print "\n---- Enter EPP frame terminated by a double newline ----\n";
while(<>)
	{
	$len = length($_) + 4;
	print STDERR "got input: $len bytes.\n";
	$header = pack("N",$len);

	if ($opt_2)
		{
		print S $header, $_, $header, $_;
		}
	elsif ($opt_d)
		{
		my $tmp = $header . $_;
		my $i;

		foreach $i (0 .. length($tmp))
			{
			print S substr($tmp,$i,1);
			print STDERR ".";
			sleep 1;
			}
		print STDERR "\n";
		}
	else
		{
		print S $header, $_;
		}

	print STDERR "Sent $len bytes.\n";

	if (sysread(S,$header,4) != 4) { die "Can't read EPP/TCP header.";}
	$len = unpack("N",$header) - 4;

	print STDERR "EPP/TCP Header: expecting $len bytes of XML\n";

	while($len > 0)
		{
		$len -= sysread(S,$in,4096);
		print $in;
		}

	print "\n---- Enter EPP frame terminated by a double newline ----\n";
	}

