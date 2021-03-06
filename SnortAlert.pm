package SnortAlert;

use strict;
use warnings;
# This is *supposed* to do the same thing as below, but doesn't seem to be 
# included in 5.14.4, or at least not as implemented for Smoothwall Express.
#use experimental 'switch';
use feature qw( switch );
no if $] >= 5.017011, warnings => 'experimental::smartmatch';

use Class::Date;

use lib ".";
use SnortAlert::Alert;

sub new {
	my $class = shift;
	my $self =  { };

	return $self;
}

sub parsealert {
	my $self = shift;
	my $rawtext = shift;
	my @lines = split(/\n/, $rawtext);
	print "Got ".scalar(@lines)." lines after split.\n";
	my $SnortAlert = SnortAlert::Alert->new;
	foreach my $line ( @lines ) {
		#[**] [1:396:11] PROTOCOL-ICMP Destination Unreachable Fragmentation Needed and DF bit was set [**]
		#[Classification: Misc activity] [Priority: 3] 
		#12/20-13:13:17.173238 00:01:5C:64:AE:46 -> 74:D4:35:86:65:6B type:0x800 len:0x24E
		#178.63.9.147 -> 70.95.130.127 ICMP TTL:46 TOS:0xC0 ID:36626 IpLen:20 DgmLen:576
		#Type:3  Code:4  DESTINATION UNREACHABLE: FRAGMENTATION NEEDED, DF SET
		#NEXT LINK MTU: 1476
		#** ORIGINAL DATAGRAM DUMP:
		#70.95.130.127:9001 -> 178.63.9.165:39229 TCP TTL:44 TOS:0x0 ID:1645 IpLen:20 DgmLen:1526 DF
		#Seq: 0x21D3EE13
		#(520 more bytes of original packet)
		#** END OF DUMP
		#[Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2015-7759][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2005-0068][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2004-0790]
		given ($line) {
			when (/\[\*\*\]\s+\[\d+:(\d+)\:\d+\]\s+([A-Z-]+)\s+(.+)\[\*\*\]/) { 
				$SnortAlert->{'sid'}			= $1; 
				$SnortAlert->{'category'}		= $2; 
				$SnortAlert->{'title'}			= $3;
			}
			when (/\[Classification\:\s+(.*?)\]\s+\[Priority\:\s+(\d)\]/) {
				$SnortAlert->{'classification'}	= $1; 
				$SnortAlert->{'priority'}		= $2; 
			}
			when (/(\d\d?)\/(\d\d?)\-(\d\d\:\d\d\:\d\d\.\d+)\s+((?:[0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2})\s+\-\>\s+((?:[0-9A-Fa-f]{2}\:){5}[0-9A-Fa-f]{2})\s+type\:/) {
				my $m = $1; my $d = $2, my $t = $3;
				my ($hms,$us) = split(/\./,$t);
				my ($H,$M,$S) = split(/\:/, $hms);
				my $y = (localtime())[5] + 1900;
				$SnortAlert->{'event_date'}		= Class::Date->new($y,$m,$d,$H,$M,$S);
				$SnortAlert->{'src_mac'}		= $4;
				$SnortAlert->{'dst_mac'}		= $5;
			}
			when (/((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\:(\d{1,5})\s+\-\>\s+((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\:(\d{1,5}).*/) {
				$SnortAlert->{'src_ip'}			= $1;
				$SnortAlert->{'src_port'}		= $2;
				$SnortAlert->{'dst_ip'}			= $3;
				$SnortAlert->{'dst_port'}		= $4;
			}
			when (/^\[Xref\s+\=\>\s+(.+)\]\[Xref\s+\=\>\s+(.+)\]\[Xref\s+\=\>\s+(.+)\]$/) {
				my $one = $1; my $two = $2; my $three = $3;
				push @{$SnortAlert->{'xrefs'}}, $one;
				push @{$SnortAlert->{'xrefs'}}, $two;
				push @{$SnortAlert->{'xrefs'}}, $three;
			}
			when (/^\[Xref\s+\=\>\s+(.+)\]\[Xref\s+\=\>\s+(.+)\]$/) {
				my $one = $1; my $two = $2;
				push @{$SnortAlert->{'xrefs'}}, $one;
				push @{$SnortAlert->{'xrefs'}}, $two;
			}
			when (/^\[Xref\s+\=\>\s+(.+)\]$/) {
				push @{$SnortAlert->{'xrefs'}}, $1;
			}
			default {
				push @{$SnortAlert->{'unmatched_lines'}}, $line;
			}
		}
	}

	return $SnortAlert;
}

1;

