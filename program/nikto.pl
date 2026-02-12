#!/usr/bin/env perl
use strict;

# Modules are now loaded in a function so errors can be trapped and evaluated
load_modules();

###############################################################################
#                               Nikto                                         #
###############################################################################
# Copyright (C) 2001 Chris Sullo
# SPDX-License-Identifier: GPL-3.0-only
#
# See the COPYING file for full information on the License Nikto is distributed under.
#
# http://cirt.net/
#######################################################################
# This program is intended for use in an authorized manner only, and the author
# can not be held liable for anything done with this program, code, or items discovered
# with this program's use.
#######################################################################

# global var/definitions
use vars qw/$TEMPLATES %CLI %VARIABLES %TESTS/;
use vars qw/%NIKTO %CONFIGFILE %COUNTERS %db_extensions %DSL_CACHE/;
use vars qw/@RESULTS @PLUGINS @DBFILE @REPORTS %CONTENTSEARCH/;

# setup
$COUNTERS{'scan_start'} = time();
$VARIABLES{'name'}      = "Nikto";
$VARIABLES{'version'}   = "2.6.0";
Getopt::Long::Configure('no_ignore_case');

# signal trap so we can close down reports properly
$SIG{'INT'} = \&safe_quit;

config_init();
setup_dirs();
require "$CONFIGFILE{'PLUGINDIR'}/nikto_core.plugin";
require "$CONFIGFILE{'PLUGINDIR'}/LW2.pm";
nprint("T:" . localtime($COUNTERS{'scan_start'}) . ": Starting", "d");

# Set SSL engine and warn if Net::SSL is used
LW2::init_ssl_engine($CONFIGFILE{'LW_SSL_ENGINE'});
if ($LW2::_SSL_LIBRARY eq 'Net::SSL') {
    nprint("+ WARNING: Net::SSL does not support SAN extraction. Use Net::SSLeay instead.");
}

general_config();
nprint("- $VARIABLES{'name'} v$VARIABLES{'version'}");
nprint($VARIABLES{'DIV'});

# No targets - quit before we do anything
if ($CLI{'host'} eq '') {
    if (!$CLI{'nocheck'}) {
        check_updates();
    }
    nprint("+ ERROR: No host (-host) specified");
    usage(1);
}

$COUNTERS{'total_targets'} = $COUNTERS{'hosts_completed'} = 0;
load_plugins();

# Parse the supplied list of targets
my @MARKS = set_targets($CLI{'host'}, $CLI{'ports'}, $CLI{'ssl'}, $CLI{'root'});

# Load tests
load_databases();
load_databases('u');

if (defined($CLI{'key'}) || defined($CLI{'cert'})) {
    $CLI{'key'}  = $CLI{'cert'} unless (defined($CLI{'key'}));
    $CLI{'cert'} = $CLI{'key'}  unless (defined($CLI{'cert'}));
}

# Open reporting
report_head();
$VARIABLES{'deferout'} = 1 unless $CLI{'display'} ne "";

# Now check each target is real and remove duplicates/fill in extra information
foreach my $mark (@MARKS) {
    $mark->{'messages'} = [];
    $mark->{'test'}     = 1;
    $mark->{'failures'} = 0;
    $mark->{'nf_cache'} = {};

    # Try to resolve the host
    my $msgs;
    ($mark->{'hostname'}, $mark->{'ip'}, $mark->{'display_name'}, $msgs) =
      resolve($mark->{'ident'});
    if ($msgs ne "") {
        push(@{ $mark->{'messages'} }, $msgs);
    }

    # Load db_tests
    set_scan_items();

    # Start hook to allow plugins to load databases etc
    run_hooks($mark, "start");

    # Skip if we can't resolve the host - we'll error later
    if (!defined $mark->{'ip'} || $mark->{'ip'} eq "") {
        $mark->{'errmsg'} = $msgs;
        $mark->{'test'}   = 0;
        next;
    }

    # Read cookies from conf & set into the cookie jar
    if (defined $CONFIGFILE{'STATIC-COOKIE'}) {
        $mark->{'cookiejar'} = LW2::cookie_new_jar();
        foreach my $p (split(/;/, $CONFIGFILE{'STATIC-COOKIE'})) {
            if ($p =~ /"([^=]+)=(.+)"/) {
                LW2::cookie_set(\%{ $mark->{'cookiejar'} }, $1, $2);
            }
        }
    }

    if (defined $CLI{'vhost'}) {
        $mark->{'vhost'} = $CLI{'vhost'};

        # Update vhost flag immediately after assignment
        $mark->{'has_vhost'} = ($mark->{'vhost'} ne '');
    }
    else {
        # Update vhost flag for existing vhost value
        $mark->{'has_vhost'} = (defined($mark->{'vhost'}) && $mark->{'vhost'} ne '');
    }
    $VARIABLES{'TEMPL_HCTR'}++;

# Check that the port is open. Return value is overloaded, either 1 for open or an error message to convey
    my $open =
      port_check(time(), $mark->{'hostname'}, $mark->{'ip'}, $mark->{'port'}, $CLI{'key'},
                 $CLI{'cert'}, $mark->{'vhost'});
    if (($open != 1) && ($open != 2)) {
        $mark->{'test'}   = 0;
        $mark->{'errmsg'} = $open;
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

# Check for updates now that proxy is set up
if (!$CLI{'nocheck'}) {
    check_updates();
}

# Now we've done the precursor, do the scan
foreach my $mark (@MARKS) {
    $NIKTO{'current_mark'}  = $mark;
    $VARIABLES{'deferout'}  = 1 unless $CLI{'display'} ne "";
    $mark->{'total_vulns'}  = 0;
    $mark->{'total_errors'} = 0;
    $mark->{'start_time'}   = time();
    report_host_start($mark);

    if (!$mark->{'test'}) {
        if ($mark->{'errmsg'} ne "") {
            $VARIABLES{'deferout'} = 0;
            add_vulnerability($mark, $mark->{'errmsg'}, "FAIL", "", "GET", "/", "", "",
                              "Failed to scan");
        }

        report_host_end($mark);
        $VARIABLES{'deferout'} = 1;
        next;
    }

    if (defined $CLI{'vhost'}) {
        $mark->{'vhost'} = $CLI{'vhost'};
    }

    # Update vhost flag after potential vhost assignment
    $mark->{'has_vhost'} = (defined($mark->{'vhost'}) && $mark->{'vhost'} ne '');

    # Saving responses
    if ($CLI{'saveresults'} ne '') {
        $mark->{'save_dir'}    = save_createdir($CLI{'saveresults'}, $mark);
        $mark->{'save_prefix'} = save_getprefix($mark);
    }

    my ($res, $content, $error, $request, $response) =
      nfetch($mark, "/", "GET", "", "", { noprefetch => 1, nopostfetch => 1 }, "Init");
    $mark->{'platform'} = platform_profiler($mark);

    # SSL info is now available - report it to all formats
    report_ssl_info($mark);

    $VARIABLES{'deferout'} = 0;
    dump_target_info($mark);

    # Now print any deferred output
    if (@{ $VARIABLES{'defertxt'} }) {
        foreach my $element (@{ $VARIABLES{'defertxt'} }) {
            my @parts  = split(/::/, $element, 3);
            my $mode   = $parts[0] || '';
            my $testid = defined($parts[1]) && $parts[1] ne '' ? $parts[1] : undef;
            my $line   = $parts[2] || $parts[1] || $element;
            nprint($line, $mode, $testid);
        }
    }
    undef $VARIABLES{'defertxt'};

    run_hooks($mark, "recon");
    run_hooks($mark, "scan");

    $mark->{'end_time'} = time();
    $mark->{'elapsed'}  = $mark->{'end_time'} - $mark->{'start_time'};

    # Use singular/plural based on count
    my $error_word = ($mark->{'total_errors'} == 1) ? "error" : "errors";
    my $item_word  = ($mark->{'total_vulns'} == 1)  ? "item"  : "items";

    if (!$mark->{'terminate'}) {
        nprint(
            "+ $COUNTERS{'totalrequests'} requests: $mark->{'total_errors'} $error_word and $mark->{'total_vulns'} $item_word reported on the remote host"
            );
    }
    else {
        nprint(
            "+ Scan terminated: $mark->{'total_errors'} $error_word and $mark->{'total_vulns'} $item_word reported on the remote host"
            );
    }
    nprint(  "+ End Time:           "
           . date_disp($mark->{'end_time'})
           . " (GMT$VARIABLES{'GMTOFFSET'}) ($mark->{'elapsed'} seconds)");
    nprint($VARIABLES{'DIV'});

    $COUNTERS{'hosts_completed'}++;
    report_host_end($mark);
}

$COUNTERS{'scan_end'}     = time();
$COUNTERS{'scan_elapsed'} = ($COUNTERS{'scan_end'} - $COUNTERS{'scan_start'});
report_summary();
report_close();

nprint("+ $COUNTERS{'hosts_completed'} host(s) tested");
nprint("+ $COUNTERS{'totalrequests'} requests made in $COUNTERS{'scan_elapsed'} seconds",
       "v", "END");

send_updates(@MARKS);

nprint("T:" . localtime() . ": Ending", "d");

exit 0;

#################################################################################
# Load config files in order
sub config_init {
    my (@CF, $home);
    my $config_exists = 0;

    # read just the --config option
    {
        my %optcfg;
        Getopt::Long::Configure('pass_through', 'noauto_abbrev');
        GetOptions(\%optcfg, "config=s");
        Getopt::Long::Configure('nopass_through', 'auto_abbrev');
        if (defined $optcfg{'config'}) { $VARIABLES{'configfile'} = $optcfg{'config'}; }
    }

    # Determine Nikto directory using FindBin (reliable even from zip/git sources)
    # Use RealBin to get absolute path even if script was invoked via symlink
    my $NIKTODIR = $FindBin::RealBin || $FindBin::Bin;
    $NIKTODIR = File::Spec->rel2abs($NIKTODIR) if defined $NIKTODIR;

    # Guess user's home directory -- to support Windows
    foreach my $var (split(/ /, "HOME USERPROFILE")) {
        $home = $ENV{$var} if ($ENV{$var});
    }

    # Read the conf files in order (local configs take precedence over system configs)
    # Priority: --config option > local configs > user home > system-wide
    push(@CF, "$VARIABLES{'configfile'}")
      if defined $VARIABLES{'configfile'} && $VARIABLES{'configfile'} ne "";
    push(@CF, File::Spec->catfile($NIKTODIR, "nikto.conf"))         if defined $NIKTODIR;
    push(@CF, File::Spec->catfile($NIKTODIR, "nikto.conf.default")) if defined $NIKTODIR;
    push(@CF, "nikto.conf");
    push(@CF, File::Spec->catfile($home, "nikto.conf")) if defined $home;

    # Only check /etc/nikto.conf on non-Windows systems
    push(@CF, "/etc/nikto.conf") unless $^O =~ /MSWin32/;

    # load in order (stop at first successful load)
    for (my $i = 0 ; $i <= $#CF ; $i++) {
        next if $CF[$i] eq "";
        if (!load_config($CF[$i])) {
            $config_exists = 1;
            last;
        }
    }

    # Couldn't find any
    if ($config_exists == 0) {
        die "- Could not find a valid nikto config file. Tried: @CF\n";
    }

    # add CONFIG{'CLIOPTS'} to ARGV if defined...
    if (defined $CONFIGFILE{'CLIOPTS'}) {
        my @t = split(/ /, $CONFIGFILE{'CLIOPTS'});
        foreach my $c (@t) { push(@ARGV, $c); }
    }

    # Check for necessary config items
    check_config_defined("CHECKMETHODS", "HEAD");
    check_config_defined('@@DEFAULT',    '@@ALL');

    return;
}

###############################################################################
sub load_modules {
    my $errors = 0;
    my @modules = ("Cwd 'abs_path'",                                        "File::Spec",
                   "FindBin",                                               "Getopt::Long",
                   "IO::Socket",                                            "JSON",
                   "List::Util qw(sum)",                                    "Net::hostent",
                   "POSIX qw(:termios_h)",                                  "Socket",
                   "Time::HiRes qw(sleep ualarm gettimeofday tv_interval)", "Time::Local",
                   "Time::Piece",                                           "Time::Seconds",
                   "XML::Writer"
                   );

    foreach my $mod (@modules) {
        eval "use $mod";
        if ($@) {

            # Allow POSIX and Time::HiRes to fail on Windows
            if (($mod =~ /^(POSIX|Time::HiRes)/) && $^O =~ /MSWin32/) {
                next;
            }
            print STDERR "ERROR: Required module not found: $mod\n";
            $errors = 1;
        }
    }

    if ($errors) { exit 1; }
}

#################################################################################
# load config file
# error=load_config(FILENAME)
sub load_config {
    my $configfile = $_[0] || return 1;

    open(CONF, "<$configfile") || return 1;   # "+ ERROR: Unable to open config file '$configfile'";
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

    return 0;
}
#################################################################################
# find plugins directory
sub setup_dirs {
    my $CURRENTDIR = abs_path($0);
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
            exit 1;
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
