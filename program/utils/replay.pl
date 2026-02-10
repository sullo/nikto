#!/usr/bin/perl
use strict;
use warnings;

###############################################################################
# SPDX-License-Identifier: GPL-3.0-only
# PURPOSE:Replay a saved request
###############################################################################
use Getopt::Long;
use JSON::PP;
use FindBin;
use File::Spec;

# Determine the program directory (parent of utils/)
# Use RealBin to get absolute path even if script was invoked via symlink
my $program_dir = File::Spec->catdir($FindBin::RealBin || $FindBin::Bin, '..');
$program_dir = File::Spec->rel2abs($program_dir);

# Define replay_usage() to avoid function name collision with nikto_core.plugin's usage()
sub replay_usage {
    print "replay.pl -- Replay a saved scan result\n";
    print "     -file 		Parse request from this file\n";
    print "     -proxy		Send request through this proxy (format: host:port)\n";
    print "     -help		Help output\n";
    exit;
}

# Save @ARGV before requiring nikto_core.plugin (it may process @ARGV)
my @saved_argv = @ARGV;

require File::Spec->catfile($program_dir, 'plugins', 'LW2.pm');
require File::Spec->catfile($program_dir, 'plugins', 'nikto_core.plugin');

# Restore @ARGV for our own GetOptions processing
@ARGV = @saved_argv;

# Initialize variables
my $infile = '';
my $proxy  = '';
my $header = '';
my $s_request;
my %request;
my %result;

LW2::http_init_request(\%request);

# options
GetOptions("help"    => \&replay_usage,
           "file=s"  => \$infile,
           "proxy=s" => \$proxy
           )
  or replay_usage();

# Check for file argument if not provided via -file
if ($infile eq '' && @ARGV > 0 && -r $ARGV[0]) {
    $infile = $ARGV[0];
}

if ($infile eq '') {
    replay_usage();
}

# load save file
if (!-r $infile) {
    print "ERROR: Argument 1 should be '-help' or a Nikto save file\n\n";
    exit 1;
}

open(my $INFILE, "<$infile") || die "Unable to open file: $!\n\n";
while (<$INFILE>) {
    if ($_ =~ /^(Test ID|Message|References):/) { $header .= $_; next; }
    next unless $_ =~ /^REQUEST:/;
    chomp;
    $_ =~ s/^REQUEST://;
    $s_request = JSON::PP->new->utf8(1)->allow_nonref(1)->decode($_);
    if (ref($s_request) ne 'HASH') {
        print "ERROR: Unable to read JSON into request structure\n";
        exit 1;
    }
}
close($INFILE);

# set into request hash
foreach my $key (keys %{$s_request}) {
    $request{$key} = $s_request->{$key};
}

# proxy
if ($proxy ne '') {
    my @p = split(/:/, $proxy);
    if (($p[0] eq '') || ($p[1] eq '') || ($p[1] =~ /[^\d]/)) {
        print "ERROR: Invalid proxy -- use 'host:port' format\n";
        exit 1;
    }
    $request{'whisker'}->{'proxy_host'} = $p[0];
    $request{'whisker'}->{'proxy_port'} = $p[1];
}

# output for the user
print "-" x 44, "  Info\n";
print "Request to:     http";
print "s" if $request{'whisker'}->{'ssl'};
print "://"
  . $request{'whisker'}->{'host'} . ":"
  . $request{'whisker'}->{'port'}
  . $request{'whisker'}->{'uri'} . "\n";
print $header;

# make request
LW2::http_fixup_request(\%request);
LW2::http_do_request_timeout(\%request, \%result);

# output for the user
print "-" x 44, "  Response\n";

# Use rebuild_response to properly format the response
print rebuild_response(\%result, 1);
