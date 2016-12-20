package SnortAlert::Alert;

use strict;
use warnings;

use Data::Dumper;

sub new {
	my $class = shift;
	my @xrefs;
	my %attrs = (
		'classification'	=>	'',
		'sid'				=>	'',
		'priority'			=>	'',
		'title'				=>	'',
		'src_ip'			=>	'',
		'dst_ip'			=>	'',
		'xrefs'				=>	\@xrefs,
	);
	my $self = \%attrs;

	bless $self, $class;
	return $self;
}

1;

