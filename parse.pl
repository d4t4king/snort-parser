#!/usr/bin/perl -w

use strict;
use warnings;

use Data::Dumper;
use Term::ANSIColor;
use File::Slurp;

use lib '.';
use SnortAlert;

my $alert_file = '/var/log/snort/alert';

my $alert_text = read_file($alert_file);
my @raw_alerts = split(/\n\n/, $alert_text);

print "Got ".scalar(@raw_alerts)." alerts.\n";

my (@parsed_alerts);
my (%titles);

foreach my $ra ( @raw_alerts ) {
	#print colored("$raw_alerts[0]\n", "bold yellow");
	my $sa = SnortAlert->parsealert($ra);
	#print Dumper($sa);
	push @parsed_alerts, $sa;
	$titles{"$sa->{'sid'}-$sa->{'title'}"}++;
}

foreach my $t ( sort { $titles{$b} <=> $titles{$a} } keys %titles ) {
	printf "%-5d %s\n", $titles{$t}, $t;
}
