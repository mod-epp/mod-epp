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

my $cert_path = "";
my $key_path = "";

my $opt_ssl = 0;

GetOptions("delay|d", \$opt_d, "duplicate|2", \$opt_2, "ssl|s", \$opt_ssl,
	"k=s", \$key_path, "c=s", \$cert_path);


if ($opt_ssl)
	{
	use Net::SSLeay  qw(die_now die_if_ssl_error);
	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::randomize();
	}


sub usage
{
print STDERR <<EOM;
Usage:

	$0 [-2] [-d] [-s] [-k keyfile] [-c certfile] host port

Connect via TCP to the specified host an port. 
Wait for a complete paragraph of text on STDIN, then send it
as an EPP/TCP frame to the host.

Options:
	-2	Duplicate each message without waiting for an answer.
	-d	delay sending.
	-s	use SSL.
	-k file use this client key.
	-c file	use this cert file.

Remarks:
	You cannot use -s and one of -d or -2.

	This is a simple half-duplex implementation.

/ol/2k2/12/04/
EOM

exit 0;
}

&usage if ($#ARGV != 1);
&usage if ($opt_ssl and ($opt_2 or $opt_d));

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

my ($ctx, $ssl);
if ($opt_ssl)
	{
	# The network connection is now open, lets fire up SSL
	
	$ctx = Net::SSLeay::CTX_new() or die_now("Failed to create SSL_CTX $!");
	Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL)
		and die_if_ssl_error("ssl ctx set options");

print STDERR "using cert/key  $cert_path, $key_path\n";
	Net::SSLeay::set_cert_and_key($ctx, $cert_path, $key_path) 
		or die_if_ssl_error("SSL cert/key");

	$ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
	Net::SSLeay::set_fd($ssl, fileno(S));   # Must use fileno
	Net::SSLeay::connect($ssl) and die_if_ssl_error("ssl connect");
	print STDERR "Cipher `" . Net::SSLeay::get_cipher($ssl) . "'\n";
	print STDERR "Server CERT `" . Net::SSLeay::dump_peer_certificate($ssl) . "'\n";
	}
	
my $len;
my $header;
my $in;

while(1)
	{
	#
	# read the frame
	#
	if ($opt_ssl)
		{ 
		$header = Net::SSLeay::read($ssl,4);
		if (!defined($header) or (length($header) != 4)) 
			{ die "Can't read EPP/TCP header.";} 
		}
	else
		{ if (sysread(S,$header,4) != 4) { die "Can't read EPP/TCP header.";} }

	$len = unpack("N",$header) - 4;

	print STDERR "EPP/TCP Header: expecting $len bytes of XML\n";

	while($len > 0)
		{
		if ($opt_ssl)
			{ $in = Net::SSLeay::read($ssl,4096);  $len -= length($in); }
		else
			{ $len -= sysread(S,$in,4096);}

		print $in;
		}
	print "\n---- Enter EPP frame terminated by a double newline ----\n";


	# get input from user;
	last unless defined($_ = <>);

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
		if ($opt_ssl)
			{
			Net::SSLeay::write($ssl, ($header . $_));
			}
		else
			{ print S $header, $_; }
		}

	print STDERR "Sent $len bytes.\n";
	}


if ($opt_ssl)
	{
	Net::SSLeay::free ($ssl);               # Tear down connection
	Net::SSLeay::CTX_free ($ctx);
	}

close S;
