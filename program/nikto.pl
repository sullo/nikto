#!/usr/bin/perl
use strict;
#VERSION,2.1.6
###############################################################################
# Modules are now loaded in a function so errors can be trapped and evaluated
load_modules();
###############################################################################
#                               Nikto                                         #
###############################################################################
#  Copyright (C) 2001 CIRT, Inc.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; version 2
#  of the License only.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to
#  Free Software Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# Contact Information:
#     Sullo (sullo@cirt.net)
#     http://cirt.net/
#######################################################################
# See the LICENSE.txt file for more information on the License Nikto is distributed under.
#
# This program is intended for use in an authorized manner only, and the author
# can not be held liable for anything done with this program, code, or items discovered
# with this program's use.
#######################################################################

# global var/definitions
use vars qw/$TEMPLATES %CLI %VARIABLES %TESTS/;
use vars qw/%NIKTO %CONFIGFILE %COUNTERS %db_extensions/;
use vars qw/@RESULTS @PLUGINS @DBFILE @REPORTS %CONTENTSEARCH/;

# setup
Getopt::Long::Configure('no_ignore_case');
$COUNTERS{'scan_start'}  = time();
$VARIABLES{'DIV'}        = "-" x 75;
$VARIABLES{'name'}       = "Nikto";
$VARIABLES{'version'}    = "2.1.6";
$VARIABLES{'configfile'} = "/etc/nikto.conf";    ### Change if it's having trouble finding it

# signal trap so we can close down reports properly
$SIG{'INT'} = \&safe_quit;

config_init();
setup_dirs();
require "$CONFIGFILE{'PLUGINDIR'}/nikto_core.plugin";
nprint("T:" . localtime($COUNTERS{'scan_start'}) . ": Starting", "d");
require "$CONFIGFILE{'PLUGINDIR'}/LW2.pm";
$VARIABLES{'GMTOFFSET'} = gmt_offset();

# use LW2;                   ### Change this line to use a different installed version

#set SSL Engine
LW2::init_ssl_engine($CONFIGFILE{'LW_SSL_ENGINE'});

my ($a, $b) = split(/\./, $LW2::VERSION);
die("- You must use LW2 2.4 or later\n") if ($a != 2 || $b < 4);

general_config();
load_databases();
load_databases('u');
nprint("- $VARIABLES{'name'} v$VARIABLES{'version'}");
nprint($VARIABLES{'DIV'});

# No targets - quit while we're ahead
if ($CLI{'host'} eq "") {
    nprint("+ ERROR: No host specified");
    usage();
}

$COUNTERS{'total_targets'} = $COUNTERS{'hosts_completed'} = 0;
load_plugins();

# Parse the supplied list of targets
my @MARKS = set_targets($CLI{'host'}, $CLI{'ports'}, $CLI{'ssl'}, $CLI{'root'});

if (defined($CLI{'key'}) || defined($CLI{'cert'})) {
    $CLI{'key'}  = $CLI{'cert'} unless (defined($CLI{'key'}));
    $CLI{'cert'} = $CLI{'key'}  unless (defined($CLI{'cert'}));
}

# Now check each target is real and remove duplicates/fill in extra information
foreach my $mark (@MARKS) {
    $mark->{'test'} = 1;
    $mark->{'failures'} = 0;

    # Try to resolve the host
    ($mark->{'hostname'}, $mark->{'ip'}, $mark->{'display_name'}) = resolve($mark->{'ident'});

    # Skip if we can't resolve the host - we'll error later
    if (!defined $mark->{'ip'}) {
        $mark->{'test'} = 0;
        next;
    }

    # Check that the port is open
    my $open =
      port_check(time(), $mark->{'hostname'}, $mark->{'ip'}, $mark->{'port'}, $CLI{'key'}, $CLI{'cert'});
    if (defined $CLI{'vhost'}) { $mark->{'vhost'} = $CLI{'vhost'} }
    if ($open == 0) {
        $mark->{'test'} = 0;
        next;
    }
    else {
        $COUNTERS{'total_targets'}++;
    }
    $mark->{'ssl'} = $open - 1;

    if ($mark->{'ssl'}) {
        $mark->{'key'}  = $CLI{'key'};
        $mark->{'cert'} = $CLI{'cert'};
    }
}

# Open reporting
report_head($CLI{'format'}, $CLI{'file'});

# Load db_tests
set_scan_items();

# Start hook to allow plugins to load databases etc
run_hooks("", "start");

# Now we've done the precursor, do the scan
foreach my $mark (@MARKS) {
    next unless ($mark->{'test'});
    $mark->{'start_time'} = time();
    $VARIABLES{'TEMPL_HCTR'}++;

    if (defined $CLI{'vhost'}) {
        $mark->{'vhost'} = $CLI{'vhost'};
    }

    # Saving responses
    if ($CLI{'saveresults'} ne '') {
        $mark->{'save_dir'} = save_createdir($CLI{'saveresults'}, $mark);
        $mark->{'save_prefix'} = save_getprefix($mark);
    }

    # Cookies
    if (defined $CONFIGFILE{'STATIC-COOKIE'}) {
        $mark->{'cookiejar'} = LW2::cookie_new_jar();

        # parse conf line into name/value pairs
        foreach my $p (split(/;/, $CONFIGFILE{'STATIC-COOKIE'})) {
            $p =~ s/(?:^\s+|\s+$)//;
            $p =~ s/"(?:[ ]+)?=(?:[ ]+)?"/","/g;
            my @cv = parse_csv($p);

            # Set into the jar
            LW2::cookie_set(\%{ $mark->{'cookiejar'} }, $cv[0], $cv[1]);
        }
    }

    $mark->{'total_vulns'}  = 0;
    $mark->{'total_errors'} = 0;

    my %FoF = ();

    nfetch($mark, "/", "GET", "", "", { noprefetch => 1, nopostfetch => 1 }, "getinfo");

    report_host_start($mark);
    if ($CLI{'findonly'}) {
        my $protocol = "http";
        if ($mark->{'ssl'}) { $protocol .= "s"; }
        if ($mark->{'banner'} eq "") {
            $mark->{'banner'} = "(no identification possible)";
        }

        add_vulnerability($mark,
                   "Server: $protocol://$mark->{'display_name'}:$mark->{'port'}\t$mark->{'banner'}",
                   0);
    }
    else {
        dump_target_info($mark);
        unless ((defined $CLI{'nofof'}) || ($CLI{'plugins'} eq '@@NONE')) { map_codes($mark) }
        run_hooks($mark, "recon");
        run_hooks($mark, "scan");
    }
    $mark->{'end_time'} = time();
    $mark->{'elapsed'}  = $mark->{'end_time'} - $mark->{'start_time'};
    if (!$CLI{'findonly'}) {
        if (!$mark->{'terminate'}) {
            nprint(
                "+ $COUNTERS{'totalrequests'} requests: $mark->{'total_errors'} error(s) and $mark->{'total_vulns'} item(s) reported on remote host"
                );
        }
        else {
            nprint(
                "+ Scan terminated:  $mark->{'total_errors'} error(s) and $mark->{'total_vulns'} item(s) reported on remote host"
                );
        }
        nprint(  "+ End Time:           "
               . date_disp($mark->{'end_time'})
               . " (GMT$VARIABLES{'GMTOFFSET'}) ($mark->{'elapsed'} seconds)");
    }
    nprint($VARIABLES{'DIV'});

    $COUNTERS{'hosts_completed'}++;
    report_host_end($mark);
}
$COUNTERS{'scan_end'}     = time();
$COUNTERS{'scan_elapsed'} = ($COUNTERS{'scan_end'} - $COUNTERS{'scan_start'});
report_summary();
report_close();

if (!$CLI{'findonly'}) {
    nprint("+ $COUNTERS{'hosts_completed'} host(s) tested");
    nprint("+ $COUNTERS{'totalrequests'} requests made in $COUNTERS{'scan_elapsed'} seconds", "v");

    send_updates(@MARKS);
}

nprint("T:" . localtime() . ": Ending", "d");

exit;

#################################################################################
# Load config files in order
sub config_init {

    # read just the --config option
    {
        my %optcfg;
        Getopt::Long::Configure('pass_through', 'noauto_abbrev');
        GetOptions(\%optcfg, "config=s");
        Getopt::Long::Configure('nopass_through', 'auto_abbrev');
        if (defined $optcfg{'config'}) { $VARIABLES{'configfile'} = $optcfg{'config'}; }
    }

    # Read the config files in order
    my ($error, $home);
    my $config_exists = 0;
    $error = load_config("$VARIABLES{'configfile'}");
    $config_exists = 1 if ($error eq "");

    # Guess home directory -- to support Windows
    foreach my $var (split(/ /, "HOME USERPROFILE")) {
        $home = $ENV{$var} if ($ENV{$var});
    }
    $error = load_config("$home/nikto.conf");
    $config_exists = 1 if ($error eq "");

    # Guess Nikto current directory
    my $NIKTODIR = $0;
    chomp($NIKTODIR);
    $NIKTODIR =~ s#[\\/]nikto.pl$##;
    $error = load_config("$NIKTODIR/nikto.conf");
    $config_exists = 1 if ($error eq "");

    $error = load_config("nikto.conf");
    $config_exists = 1 if ($error eq "");

    if ($config_exists == 0) {
        die "- Could not find a valid nikto config file\n";
    }

    return;
}

###############################################################################
sub load_modules {
        my $errors=0;
	my @modules = qw/Getopt::Long Time::Local IO::Socket/;
	push(@modules,"List::Util qw(sum)");
	foreach my $mod (@modules) { 
		eval "use $mod";
        	if ($@) { 
			print "ERROR: Required module not found: $mod\n"; 
			$errors=1; 
		}
	}

	@modules = ();
	push(@modules,"Time::HiRes qw(ualarm gettimeofday tv_interval)");
	push(@modules,"POSIX qw(:termios_h)");
	foreach my $mod (@modules) { 
		eval "use $mod";
		if ($@ && $^O !~ /MSWin32/) {
			# Allow this to work on Windows
			if ($@) { print "ERROR: Required module not found: $mod\n"; $errors=1; }
		}
	}

	if ($errors) { exit; }
}

#################################################################################
# load config file
# error=load_config(FILENAME)
sub load_config {
    my $configfile = $_[0];

    open(CONF, "<$configfile") || return "+ ERROR: Unable to open config file '$configfile'";
    my @CONFILE = <CONF>;
    close(CONF);

    foreach my $line (@CONFILE) {
        $line =~ s/\#.*$//;
        chomp($line);
        $line =~ s/\s+$//;
        $line =~ s/^\s+//;
        next if ($line eq "");
        my @temp = split(/=/, $line, 2);
        if ($temp[0] ne "") { $CONFIGFILE{ $temp[0] } = $temp[1]; }
    }

    # add CONFIG{'CLIOPTS'} to ARGV if defined...
    if (defined $CONFIGFILE{'CLIOPTS'}) {
        my @t = split(/ /, $CONFIGFILE{'CLIOPTS'});
        foreach my $c (@t) { push(@ARGV, $c); }
    }

    # Check for necessary config items
    check_config_defined("CHECKMETHODS", "HEAD");
    check_config_defined('@@MUTATE',     'dictionary;subdomain');
    check_config_defined('@@DEFAULT',    '@@ALL,-@@MUTATE');

    return "";
}
#################################################################################
# find plugins directory
sub setup_dirs {
    my $CURRENTDIR = $0;
    chomp($CURRENTDIR);
    $CURRENTDIR =~ s#[\\/]nikto.pl$##;
    $CURRENTDIR = "." if $CURRENTDIR =~ /^nikto.pl$/;

    # First assume we get it from CONFIGFILE
    unless (defined $CONFIGFILE{'EXECDIR'}) {
        if (-d "$ENV{'PWD'}/plugins") {
            $CONFIGFILE{'EXECDIR'} = $ENV{'PWD'};
        }
        elsif (-d "$CURRENTDIR/plugins") {
            $CONFIGFILE{'EXECDIR'} = $CURRENTDIR;
        }
        elsif (-d "./plugins") {
            $CONFIGFILE{'EXECDIR'} = $CURRENTDIR;
        }
        else {
            print STDERR "Could not work out the nikto EXECDIR, try setting it in nikto.conf\n";
            exit;
        }
    }
    unless (defined $CONFIGFILE{'PLUGINDIR'}) {
        $CONFIGFILE{'PLUGINDIR'} = "$CONFIGFILE{'EXECDIR'}/plugins";
    }
    unless (defined $CONFIGFILE{'TEMPLATEDIR'}) {
        $CONFIGFILE{'TEMPLATEDIR'} = "$CONFIGFILE{'EXECDIR'}/templates";
    }
    unless (defined $CONFIGFILE{'DOCDIR'}) {
        $CONFIGFILE{'DOCDIR'} = "$CONFIGFILE{'EXECDIR'}/docs";
    }
    unless (defined $CONFIGFILE{'DBDIR'}) {
        $CONFIGFILE{'DBDIR'} = "$CONFIGFILE{'EXECDIR'}/databases";
    }
    return;
}

######################################################################
## check_config_defined(item, default)
## Checks whether config has been set, warns and sets to a default
sub check_config_defined {
    my $item    = $_[0];
    my $default = $_[1];

    if (!defined $CONFIGFILE{$item}) {
        print STDERR
          "- Warning: $item is not defined in Nikto configuration, setting to \"$default\"\n";
        $CONFIGFILE{$item} = $default;
    }

    return;
}
