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
my (%titles,%sources,%sort_by_event_count,%sort_by_alert_count);

foreach my $ra ( @raw_alerts ) {
	#print colored("$raw_alerts[0]\n", "bold yellow");
	my $sa = SnortAlert->parsealert($ra);
	#print Dumper($sa);
	push @parsed_alerts, $sa;
	$titles{"$sa->{'sid'}-$sa->{'title'}"}++;
	$sources{$sa->{'src_ip'}}{"$sa->{'priority'}-$sa->{'title'}"}++;
}

foreach my $t ( sort { $titles{$b} <=> $titles{$a} } keys %titles ) {
	printf "%-5d %s\n", $titles{$t}, $t;
}
my @sorted_src_ips = map substr($_, 4) => sort map pack('C4' => /(\d+)\.(\d+)\.(\d+)\.(\d+)/) . $_ => keys %sources;
foreach my $src ( keys %sources ) { 
	$sort_by_alert_count{$src} = scalar(keys(%{$sources{$src}}));
	my $tot_ev = 0;
	foreach my $evt ( keys %{$sources{$src}} ) {
		$sort_by_event_count{$src} += $sources{$src}{$evt};
	}
}
foreach my $src ( sort { $sort_by_alert_count{$b} <=> $sort_by_alert_count{$a} } keys %sources ) {
	print "$src:\n";
	foreach my $evt ( sort { $sources{$src}{$b} <=> $sources{$src}{$a} } keys %{$sources{$src}} ) {
		printf "%7d %-s\n", $sources{$src}{$evt}, $evt;
		#print "K: $evt; V: $sources{$src}{$evt}\n";
	}
	#print "\t".Dumper(\%{$sources{$s}});
}
