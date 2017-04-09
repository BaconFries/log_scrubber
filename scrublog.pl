#!/usr/bin/perl

use strict;
use warnings;
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
use IO::Compress::Gzip qw(gzip $GzipError);
use File::Basename;
use Time::HiRes 'gettimeofday', 'tv_interval';
use Getopt::Long;
use POSIX qw(strftime);
use Log::Log4perl;

my $timestamp = strftime '%Y%m%d_%H%M', gmtime();

# Initialize Logger
my $log_conf = qq(
   log4perl.rootLogger              = DEBUG, LOG1
   log4perl.appender.LOG1           = Log::Log4perl::Appender::File
   log4perl.appender.LOG1.filename  = ./scrublog_$timestamp.log
   log4perl.appender.LOG1.mode      = append
   log4perl.appender.LOG1.layout    = Log::Log4perl::Layout::PatternLayout
   log4perl.appender.LOG1.layout.ConversionPattern = %d %p %m %n
);
Log::Log4perl::init( \$log_conf );
my $logger = Log::Log4perl->get_logger();
$logger->info("#Log Scrubber Started#");

my $start = [ gettimeofday() ];
my $filename;
my $file;
my $dir;
my $dryrun;
my $logmatch;
my $help = 0;

#my $regex = qr/\b([13-6](?:\d[-\s]??){12,15})\b/;
my $regex = qr/\b(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b/;

my @filelist;

sub usage {
    my $message = $_[0];
    if ( defined $message && length $message ) {
        $message .= "\n"
          unless $message =~ /\n$/;
    }

    my $command = $0;
    $command =~ s#^.*/##;

    print STDERR (
        $message,
        "usage: $command\n"
          . "  -h ,--help\n"
          . "  --filelist <file with list of logs to process>\n"
          . "  --file <log file to process>\n"
          . "  --dir <directory with logs to process>\n"
          . "  --dryrun\n     log what would be done\n"
          . "  --logmatch\n     log information on matches, very verbose\n"
    );
    die("\n");
}

GetOptions(
    "filelist=s"   => \$filename,
    "file=s"   => \$file,
    "dir=s"    => \$dir,
    "dryrun"   => \$dryrun,
    "logmatch" => \$logmatch,
    "help"     => \$help,
    "h"        => \$help,
) or usage("Error in command line arguments\n");

usage("help") if $help;

if ($dryrun) {
    $logger->info("Dry Run set, not creating files.");
}
if ($logmatch) {
    $logger->info("Log Match set, logging additional match details.");
}

if ( $filename && $dir ) {
    $logger->fatal("Can't set both filelist and dir\n");
}
if ( $filename && $file ) {
    $logger->fatal("Can't set both file and file\n");
}
if ( $file && $dir ) {
    $logger->fatal("Can't set both file and dir\n");
}


if ( !$filename && !$dir && !$file ) {
    $logger->info(
"No file, filelist, or directory provided, using current working directory: $ENV{PWD}"
    );
    $dir = '.';
}

if ($filename) {
    $logger->info("File $filename provided.");
    open( my $fh, '<:encoding(UTF-8)', $filename )
      or $logger->fatal("Could not open file '$filename' $!");
    while (<$fh>) {
        chomp;
        push @filelist, $_;
    }
    close $fh;
}

if ($file) {
    push @filelist, $file;
}

if ($dir) {
    opendir my $dh, $dir
      or $logger->fatal("Could not open '$dir' for reading '$!'");
    @filelist = readdir $dh;
    closedir $dh;
}

@filelist = grep { $_ =~ /gz$/ } @filelist;
unless ( scalar @filelist ) {
    $logger->fatal("No gz files given.");
}

foreach (@filelist) {
    if ( -e $_ ) {
        $logger->info("File to scrub: $_");
    }
    else {
        $logger->warn("File doesn't exist or can't read: $_");
    }
}

unless ( -e "scrubbedlogs/" ) {
    mkdir "scrubbedlogs/";
}

foreach my $filename (@filelist) {
    my $iteration_start = [ gettimeofday() ];
    my ( $file, $dir ) = fileparse($filename);
    chomp $file;
    chomp $filename;
    my $input  = $dir . $file;
    my $output = "scrubbedlogs/" . $file;
    $logger->info("src: $input => dst: $ENV{PWD}/$output");
    if ( !-e $input ) {
        $logger->warn("File doesn't exist or can't read: $input");
        next;
    }
    my $unzip = new IO::Uncompress::Gunzip $input
      or $logger->fatal("IO::Uncompress::Gunzip failed: $GunzipError");
    my $zip;
    unless ($dryrun) {
        $zip = IO::Compress::Gzip->new($output)
          or $logger->fatal("Could not write to $output: $GzipError");
    }
    my $cnt = 0;
    while ( my $line = <$unzip> ) {
        my @matches = all_match_positions( $regex, $line );
        foreach my $o (@matches) {
            my $m = substr( $line, $$o[0], $$o[2] );
            chomp($m);
            if ( &luhn_test($m) ) {
                if ($logmatch) {
                    my $bm = '';
                    my $am = '';
                    my $r  = ( length($line) - $$o[1] - 2 );

                    if ( $$o[0] <= 4 ) {
                        $bm = substr( $line, 0, $$o[0] );
                    }
                    elsif ( $$o[0] > 4 ) {
                        $bm = substr( $line, ( $$o[0] - 5 ), 5 );
                    }

                    if ( $r <= 4 && $r > 0 ) {
                        $am = substr( $line, $$o[1], $r );
                    }
                    if ( $r > 4 ) {
                        $am = substr( $line, $$o[1], 5 );
                    }

$logger->info( sprintf( "match: %-5s %-20s %-5s #%-3d line %-7d offset %4d, %-4d",  $bm, $m, $am, $cnt, $., $$o[0], $$o[1]) );
                }
                unless ($dryrun) {
                    my $mask = 'x' x length($m);
                    substr( $line, $$o[0], $$o[2] ) = $mask;
                }
                $cnt++;
            }
        }
        unless ($dryrun) {
            print {$zip} $line;
        }
    }
    $logger->info("replacements: $cnt");
    $logger->info( "elapsed secs: " . tv_interval($iteration_start) );
}

my $total_secs = tv_interval($start);
$logger->info( "total minutes: " . ( $total_secs / 60 ) );

sub luhn_test {
    my $v = $_[0];
    $v =~ s/\D//g;
    my @rev = reverse split //, $v;
    my ( $sum1, $sum2, $i ) = ( 0, 0, 0 );

    for ( my $i = 0 ; $i < @rev ; $i += 2 ) {
        $sum1 += $rev[$i];
        last if $i == $#rev;
        $sum2 += 2 * $rev[ $i + 1 ] % 10 + int( 2 * $rev[ $i + 1 ] / 10 );
    }
    return ( $sum1 + $sum2 ) % 10 == 0;
}

sub all_match_positions {
    my ( $regex, $string ) = @_;
    my @ret;
    while ( $string =~ /$regex/g ) {
        push @ret,
          [ ( pos($string) - length $1 ), pos($string) - 1, length($1) ];
    }
    return @ret;
}
