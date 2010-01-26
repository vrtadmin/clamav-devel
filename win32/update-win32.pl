#!/usr/bin/perl

use strict;
use warnings;
use XML::Twig;
use File::Copy;
use File::Temp 'tempfile';


#########################################################
# HACK HERE  HACK HERE  HACK HERE  HACK HERE  HACK HERE # 
#########################################################

use constant DEBUG => 0;

# CLAMAV-CONFIG.H MACROES
# - Set to the proper win32 value or -1 to undef - #
my %CONF = (
    'AC_APPLE_UNIVERSAL_BUILD' => -1,
    'ANONYMOUS_MAP' => -1,
    'BIND_8_COMPAT' => -1,
    'BUILD_CLAMD' => '1',
    'CLAMAVGROUP' => '"clamav"',
    'CLAMAVUSER' => '"clamav"',
    'CLAMUKO' => -1,
    'CL_DEBUG' => -1,
    'CL_EXPERIMENTAL' => -1,
    'CL_THREAD_SAFE' => '1',
    'CONFDIR' => '"C:\\\\ClamAV"',
    'CURSES_INCLUDE' => -1,
    'C_AIX' => -1,
    'C_BEOS' => -1,
    'C_BIGSTACK' => -1,
    'C_BSD' => -1,
    'C_DARWIN' => -1,
    'C_GNU_HURD' => -1,
    'C_HPUX' => -1,
    'C_INTERIX' => -1,
    'C_IRIX' => -1,
    'C_KFREEBSD_GNU' => -1,
    'C_LINUX' => -1,
    'C_OS2' => -1,
    'C_OSF' => -1,
    'C_QNX6' => -1,
    'C_SOLARIS' => -1,
    'DATADIR' => '"C:\\\\ClamAV\\\\db"',
    'DEFAULT_FD_SETSIZE' => '1024',
    'FDPASS_NEED_XOPEN' => -1,
    'FILEBUFF' => '8192',
    'FPU_WORDS_BIGENDIAN' => '0',
    'FRESHCLAM_DNS_FIX' => -1,
    'FRESHCLAM_NO_CACHE' => -1,
    'HAVE_ARGZ_ADD' => -1,
    'HAVE_ARGZ_APPEND' => -1,
    'HAVE_ARGZ_COUNT' => -1,
    'HAVE_ARGZ_CREATE_SEP' => -1,
    'HAVE_ARGZ_H' => -1,
    'HAVE_ARGZ_INSERT' => -1,
    'HAVE_ARGZ_NEXT' => -1,
    'HAVE_ARGZ_STRINGIFY' => -1,
    'HAVE_ATTRIB_ALIGNED' => -1,
    'HAVE_ATTRIB_PACKED' => -1,
    'HAVE_BZLIB_H' => '1',
    'HAVE_CLOSEDIR' => '1',
    'HAVE_CTIME_R' => '1',
    'HAVE_CTIME_R_2' => '1',
    'HAVE_CTIME_R_3' => -1,
    'HAVE_DECL_CYGWIN_CONV_PATH' => -1,
    'HAVE_DIRENT_H' => '1',
    'HAVE_DLD' => -1,
    'HAVE_DLD_H' => -1,
    'HAVE_DLERROR' => -1,
    'HAVE_DLFCN_H' => '1',
    'HAVE_DL_H' => -1,
    'HAVE_DYLD' => -1,
    'HAVE_ERROR_T' => -1,
    'HAVE_FD_PASSING' => -1,
    'HAVE_FSEEKO' => '1',
    'HAVE_GETADDRINFO' => '1',
    'HAVE_GETPAGESIZE' => '1',
    'HAVE_GRP_H' => -1,
    'HAVE_ICONV' => -1,
    'HAVE_INET_NTOP' => '1',
    'HAVE_INITGROUPS' => -1,
    'HAVE_INTTYPES_H' => -1,
    'HAVE_IN_ADDR_T' => -1,
    'HAVE_IN_PORT_T' => '1',
    'HAVE_LIBCHECK' => -1,
    'HAVE_LIBDL' => '1',
    'HAVE_LIBDLLOADER' => '1',
    'HAVE_LIBMILTER_MFAPI_H' => -1,
    'HAVE_LIBNCURSES' => -1,
    'HAVE_LIBPDCURSES' => -1,
    'HAVE_LIBZ' => '1',
    'HAVE_LIMITS_H' => '1',
    'HAVE_LTDL' => '1',
    'HAVE_MACH_O_DYLD_H' => -1,
    'HAVE_MADVISE' => -1,
    'HAVE_MALLINFO' => -1,
    'HAVE_MALLOC_H' => '1',
    'HAVE_MEMCPY' => '1',
    'HAVE_MEMORY_H' => '1',
    'HAVE_MKSTEMP' => '1',
    'HAVE_MMAP' => -1,
    'HAVE_NDIR_H' => -1,
    'HAVE_OPENDIR' => '1',
    'HAVE_POLL' => '1',
    'HAVE_POLL_H' => '1',
    'HAVE_PRAGMA_PACK' => '1',
    'HAVE_PRAGMA_PACK_HPPA' => -1,
    'HAVE_PRELOADED_SYMBOLS' => -1,
    'HAVE_PTHREAD_YIELD' => '1',
    'HAVE_PWD_H' => -1,
    'HAVE_READDIR' => '1',
    'HAVE_READDIR_R_2' => -1,
    'HAVE_READDIR_R_3' => -1,
    'HAVE_RECVMSG' => '1',
    'HAVE_RESOLV_H' => '1',
    'HAVE_SAR' => '1',
    'HAVE_SCHED_YIELD' => -1,
    'HAVE_SENDMSG' => '1',
    'HAVE_SETGROUPS' => -1,
    'HAVE_SETSID' => '1',
    'HAVE_SHL_LOAD' => -1,
    'HAVE_SNPRINTF' => '1',
    'HAVE_STDBOOL_H' => -1,
    'HAVE_STDINT_H' => -1,
    'HAVE_STDLIB_H' => '1',
    'HAVE_STRCASESTR' => -1,
    'HAVE_STRERROR_R' => '1',
    'HAVE_STRINGS_H' => -1,
    'HAVE_STRING_H' => '1',
    'HAVE_STRLCAT' => -1,
    'HAVE_STRLCPY' => -1,
    'HAVE_SYSCONF_SC_PAGESIZE' => -1,
    'HAVE_SYSTEM_TOMMATH' => -1,
    'HAVE_SYS_DL_H' => -1,
    'HAVE_SYS_FILIO_H' => -1,
    'HAVE_SYS_INTTYPES_H' => -1,
    'HAVE_SYS_INT_TYPES_H' => -1,
    'HAVE_SYS_MMAN_H' => -1,
    'HAVE_SYS_PARAM_H' => -1,
    'HAVE_SYS_SELECT_H' => -1,
    'HAVE_SYS_STAT_H' => '1',
    'HAVE_SYS_TYPES_H' => '1',
    'HAVE_SYS_UIO_H' => -1,
    'HAVE_TERMIOS_H' => -1,
    'HAVE_UNISTD_H' => -1,
    'HAVE_VSNPRINTF' => '1',
    'HAVE_WORKING_ARGZ' => -1,
    'LIBCLAMAV_FULLVER' => '"6.0.4"',
    'LIBCLAMAV_MAJORVER' => '6',
    'LTDL_DLOPEN_DEPLIBS' => -1,
    'LT_DLSEARCH_PATH' => '""',
    'LT_LIBEXT' => '"dll"',
    'LT_MODULE_EXT' => '".dll"',
    'LT_MODULE_PATH_VAR' => '"LD_LIBRARY_PATH"',
    'LT_OBJDIR' => '""',
    'NDEBUG' => '1',
    'NEED_USCORE' => -1,
    'NOBZ2PREFIX' => -1,
    'NO_FD_SET' => -1,
    'PACKAGE' => 'PACKAGE_NAME',
    'PACKAGE_BUGREPORT' => '"http://bugs.clamav.net/"',
    'PACKAGE_NAME' => '"ClamAV"',
    'PACKAGE_STRING' => '"ClamAV devel"',
    'PACKAGE_TARNAME' => '"clamav"',
    'PACKAGE_URL' => '"http://www.clamav.net/"',
    'PACKAGE_VERSION' => '"devel"',
    'SCANBUFF' => '131072',
    'SETPGRP_VOID' => '1',
    'SIZEOF_INT' => '4',
    'SIZEOF_LONG' => '4',
    'SIZEOF_LONG_LONG' => '8',
    'SIZEOF_SHORT' => '2',
    'SIZEOF_VOID_P' => '4',
    'STDC_HEADERS' => '1',
    'SUPPORT_IPv6' => -1,
    'USE_MPOOL' => -1,
    'USE_SYSLOG' => -1,
    'VERSION_SUFFIX' => '""',
    'WORDS_BIGENDIAN' => '0',
    '_LARGEFILE_SOURCE' => -1,
    '_POSIX_PII_SOCKET' => -1,
    '_REENTRANT' => '1',
    '_THREAD_SAFE' => -1,
    '__error_t_defined' => -1,
    'const' => -1,
    'error_t' => -1,
    'inline' => '_inline',
    'off_t' => -1,
    'restrict' => -1,
    'socklen_t' => -1,
    );


# PROJECT FILES #
# - makefile: path to Makefile.am from the root of the repo
# - sections: section of Makefile.am to parse (without _SOURCES or _la_SOURCES)
# - output: path to the output vcproj file
# - makefile_only: *optional* regex to allow exclusion of certain files from the vcproj (use double escapes)
# - vcproj_only: *optional* regex to allow inclusion of certain files into the vcproj (use double escapes)

my @PROJECTS = (
    # LIBCLAMAV #
    {makefile => 'libclamav', sections => ['libclamav', 'libclamav_internal_utils'], output => 'win32/libclamav.vcproj', makefile_only => 'BraIA64\\.c$', vcproj_only => '(3rdparty\\\\|compat\\\\|getopt\\.c|misc\\.c)'},

    # LIBCLAMUNRAR_IFACE #
    {makefile => 'libclamav', sections => ['libclamunrar_iface'], output => 'win32/libclamunrar_iface.vcproj', vcproj_only => 'compat\\\\'},

    # LIBCLAMUNRAR #
    {makefile => 'libclamav', sections => ['libclamunrar'], output => 'win32/libclamunrar.vcproj'},

    # CLAMSCAN #
    {makefile => 'clamscan', sections => ['clamscan'], output => 'win32/clamscan.vcproj', makefile_only => 'optparser\\.c$', vcproj_only => 'compat\\\\'},

    # FRESHCLAM #
    {makefile => 'freshclam', sections => ['freshclam'], output => 'win32/freshclam.vcproj', makefile_only => 'optparser\\.c$', vcproj_only => 'compat\\\\'},

    # CLAMCONF #
    {makefile => 'clamconf', sections => ['clamconf'], output => 'win32/clamconf.vcproj', makefile_only => 'optparser\\.c$'},

    # CLAMBC #
    {makefile => 'clambc', sections => ['clambc'], output => 'win32/clambc.vcproj', makefile_only => 'optparser\\.c$'},

    # LLVMsystem #
    {makefile => 'libclamav/c++', sections => ['libllvmsystem'], output => 'win32/LLVMsystem.vcproj'},

    # LLVMsupport #
    {makefile => 'libclamav/c++', sections => ['libllvmsupport'], output => 'win32/LLVMsupport.vcproj'},

    # LLVMcodgen #
    {makefile => 'libclamav/c++', sections => ['libllvmcodegen'], output => 'win32/LLVMcodegen.vcproj'},

    # LLVMcodgen #
    {makefile => 'libclamav/c++', sections => ['libllvmx86codegen'], output => 'win32/LLVMx86codegen.vcproj'},

    # LLVMjit #
    {makefile => 'libclamav/c++', sections => ['libllvmjit'], output => 'win32/LLVMjit.vcproj', makefile_only => '\\\\llvm\\\\lib\\\\Support\\\\'},


    );

###########################################################
# STOP HACKING HERE  STOP HACKING HERE  STOP HACKING HERE # 
###########################################################




my %ref_files;
my %files;
my $exclude;
my $do_patch = 0;

sub ugly_print {
    no warnings 'recursion';
    my ($t, $fh) = @_;
    return unless $t;
    my $haveatt = 0;

    print $fh "\t" x $t->level;
    print $fh "<".$t->gi;
    if(scalar keys %{$t->atts}) {
	print $fh "\n";
	foreach (sort keys %{$t->atts}) {
	    print $fh "\t" x ($t->level + 1);
	    print $fh $_.'="'.$t->atts->{$_}."\"\n";
	}
	$haveatt = 1;
    }

    my $is_stupid_tag = $t->gi =~ /^(File|ToolFiles|References|Globals|Filter)$/;
    if($haveatt) {
	print $fh "\t" x $t->level;
	print $fh "\t" if $t->children || $is_stupid_tag;
    }
    print $fh "/" unless $t->children || $is_stupid_tag;
    print $fh ">\n";
    ugly_print($t->first_child, $fh);
    if($t->children || $is_stupid_tag) {
	print $fh "\t" x $t->level;
	print $fh "</".$t->gi.">\n";
    }
    ugly_print($t->next_sibling, $fh);
}

sub file {
    my ($twig, $file) = @_;
    my $fname = $file->{'att'}->{'RelativePath'};
    return unless $fname =~ /^.*\.c(pp)?$/;
    return if defined($exclude) && $fname =~ /$exclude/;
    $file->delete unless !$do_patch || exists $ref_files{$fname};
    $files{$fname} = 1;
}

$do_patch = $#ARGV == 0 && $ARGV[0] eq '--regen';
die("Usage:\nupdate-win32.pl [--regen]\n\nChecks the win32 build system and regenerates it if --regen is given\n\n") if $#ARGV == 0 && $ARGV[0] eq '--help';
my $BASE_DIR = `git rev-parse --git-dir`;
chomp($BASE_DIR);
die "This script only works in a GIT repository\n" unless $BASE_DIR;
$BASE_DIR = "$BASE_DIR/..";
my $VER = `git describe --always`;
chomp($VER);
die "Cannot determine git version via git-describe\n" unless $VER && !$?;
$VER = "devel-$VER";
my $w = 0;

print "Processing clamav-config.h...\n";

open IN, "< $BASE_DIR/clamav-config.h.in" || die "Cannot find clamav-config.h.in: $!\n";
$do_patch and open OUT, "> $BASE_DIR/win32/clamav-config.h" || die "Cannot open clamav-config.h: $!\n";
$do_patch and  print OUT "/* clamav-config.h.  Generated from clamav-config.h.in by update-win32.  */\n\n";
while(<IN>) {
    if(!/^#\s*undef (.*)/) {
	$do_patch and print OUT $_;
	next;
    }
    if($1 eq 'VERSION') {
	$do_patch and print OUT "#define VERSION \"$VER\"\n";
	next;
    }
    if(!exists($CONF{$1})) {
	warn "Warning: clamav-config.h option '$1' is unknown. Please take a second to update this script.\n";
	$do_patch and print OUT "/* #undef $1 */\n";
	$w++;
	next;
    }
    if($CONF{$1} eq -1) {
	$do_patch and print OUT "/* #undef $1 */\n";
    } else {
	$do_patch and print OUT "#define $1 $CONF{$1}\n";
    }
}
close IN;
if($do_patch) {
    close OUT;
    print "clamav-config.h generated ($w warnings)\n";
} else {
    print "clamav-config.h.in parsed ($w warnings)\n";
}
foreach (@PROJECTS) {
    my %proj = %$_;
    %files = ();
    %ref_files = ();
    my $got = 0;
    $exclude = $proj{'vcproj_only'};
    print "Parsing $proj{'output'}...\n";
    open IN, "$proj{'makefile'}/Makefile.am" or die "Cannot open $proj{'makefile'}/Makefile.am\n";
    while(<IN>) {
	my ($trail, $fname);
	if($got == 0) {
	    next unless /^(.*?)(?:_la)?_SOURCES\s*\+?=\s*(.*?)\s*(\\)?\s*$/;
	    next unless grep {$_ eq $1} (@{$proj{'sections'}});
	    $got = 1;
	    $trail = $3;
	    $fname = $2;
	} else {
	    /^\s*(.*?)(\s*\\)?$/;
	    $trail = $2;
	    $fname = $1;
	}
	if($fname =~ /\.c(pp)?$/) {
	    if($fname =~ s/^(\$\(top_srcdir\)|\.\.)\///) {
		$fname = "../$fname";
	    } else {
		$fname = "../$proj{'makefile'}/$fname";
	    }
            $fname =~ y/\//\\/;
	    $ref_files{$fname} = 1 unless defined($proj{'makefile_only'}) && $fname =~ /$proj{'makefile_only'}/;
	}
	$got = 0 unless $trail;
    }
    close IN;

    my $xml = XML::Twig->new( keep_encoding => 1, twig_handlers => { File => \&file } );
    $xml->parsefile("$BASE_DIR/$proj{'output'}");

    my @missing_in_vcproj = grep ! exists $files{$_}, keys %ref_files;
    my @missing_in_makefile = grep ! exists $ref_files{$_}, keys %files;

    if($do_patch) {
	if($#missing_in_vcproj >=0) {
	    my $filter;
	    die("Cannot locate a proper filter in $proj{'output'}\n") unless $xml->root->first_child('Files') && $xml->root->first_child('Files')->first_child('Filter');
	    foreach ($xml->root->first_child('Files')->children('Filter')) {
		next unless $_->att('Name') =~ /^Source Files$/i;
		$filter = $_;
		last;
	    }
	    $filter = $xml->root->first_child('Files')->first_child('Filter') unless defined($filter);
	    foreach (@missing_in_vcproj) {
		my $addfile = $xml->root->new('File');
		$addfile->set_att('RelativePath' => $_);
		$addfile->paste($filter);
		warn "Warning: File $_ not in $proj{'output'}: added!\n" foreach @missing_in_vcproj;
	    }
	}
	warn "Warning: File $_ not in $proj{'makefile'}/Makefile.am: deleted!\n" foreach @missing_in_makefile;
	my ($fh, $filename) = tempfile();
	print $fh "<?xml version=\"1.0\" encoding=\"Windows-1252\"?>\n";
	ugly_print($xml->root, $fh);
	close $fh;
	move($filename, "$proj{'output'}");
	print "Regenerated $proj{'output'} (".($#missing_in_vcproj + $#missing_in_makefile + 2)." changes)\n";
    } else {
	warn "Warning: File $_ not in $proj{'output'}\n" foreach @missing_in_vcproj;
	warn "Warning: File $_ not in $proj{'makefile'}/Makefile.am\n" foreach @missing_in_makefile;
	print "Parsed $proj{'output'} (".($#missing_in_vcproj + $#missing_in_makefile + 2)." warnings)\n";
    }
}
