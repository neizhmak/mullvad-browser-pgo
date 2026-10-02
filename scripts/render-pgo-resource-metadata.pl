#!/usr/bin/env perl
# Actual warm RBM metadata only; offline namespace/deadline are caller-owned.
use strict;
use warnings;
use Getopt::Long qw(GetOptionsFromArray);
use Cwd qw(abs_path getcwd);
use File::Spec;
use File::Temp qw(tempdir);
use Fcntl qw(O_WRONLY O_CREAT O_EXCL O_NOFOLLOW);
use Digest::SHA qw(sha256_hex);
use JSON::PP;
use Encode qw(encode);
no warnings 'once';

my ($upstream, $output);
my @args = @ARGV;
Getopt::Long::Configure('no_auto_abbrev', 'no_ignore_case');
my $parsed;
{ local $SIG{__WARN__} = sub {};
  $parsed = GetOptionsFromArray(\@args, 'upstream=s' => \$upstream,
                                'output-directory=s' => \$output); }
sub fail { die "resource_metadata_failure\n"; }
if (!$parsed || @args || !defined($upstream) || !defined($output)) {
    print STDERR "PGO resource metadata arguments rejected.\n";
    exit 2;
}

sub safe_directory {
    my ($value, $create) = @_;
    fail() if $value =~ /[\x00-\x1f\x7f]/ || length($value) > 4096;
    my $absolute = File::Spec->rel2abs($value);
    my @parts = File::Spec->splitdir($absolute);
    fail() if grep { $_ eq '..' || $_ eq '.' } @parts;
    my $current = '/';
    for my $part (@parts) {
        next unless length $part;
        $current = File::Spec->catdir($current, $part);
        fail() if -l $current;
        if (!-e $current && $create) { mkdir($current, 0700) or fail(); }
        fail() unless -d $current;
    }
    return abs_path($absolute) // fail();
}

sub write_public {
    my ($directory, $name, $bytes) = @_;
    fail() unless length($bytes) <= 1024 * 1024;
    my $path = File::Spec->catfile($directory, $name);
    sysopen(my $handle, $path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) or fail();
    binmode($handle, ':raw') or fail();
    print {$handle} $bytes or fail();
    close($handle) or fail();
}

sub current_affinity {
    open(my $handle, '<', '/proc/self/status') or fail();
    my $line;
    while (my $value = <$handle>) {
        $line = $1 if $value =~ /^Cpus_allowed_list:\s*([^\r\n]+)[\r\n]*$/;
    }
    close($handle) or fail();
    fail() unless defined($line) && $line =~ /^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/;
    my @cpus;
    for my $part (split /,/, $line) {
        my ($first, $last) = split /-/, $part;
        $last //= $first;
        fail() if $first > $last || $last > 1048576 || @cpus + $last - $first + 1 > 4096;
        push @cpus, $first .. $last;
    }
    fail() unless @cpus;
    return \@cpus;
}

sub logical_cpu_count {
    open(my $handle, '<', '/proc/cpuinfo') or fail();
    my ($count, $lines) = (0, 0);
    while (my $line = <$handle>) {
        fail() if ++$lines > 1000000 || length($line) > 8192;
        ++$count if $line =~ /^processor\s*:\s*\d+\s*$/;
    }
    close($handle) or fail();
    fail() unless $count >= 1 && $count <= 1048576;
    return $count;
}

my ($mozconfig, $build, $metadata, $tiny_digest, $atomic_evidence);
# Keep the standard descriptor numbers for RBM::CaptureExec/Capture::Tiny.
# Localizing globs can move STDOUT away from fd1 and break native nproc capture.
open(my $saved_stdout, '>&', \*STDOUT) or fail();
open(my $saved_stderr, '>&', \*STDERR) or fail();
my $ok = eval {
    open(STDOUT, '>', File::Spec->devnull()) or fail();
    open(STDERR, '>', File::Spec->devnull()) or fail();
    $upstream = safe_directory($upstream, 0);
    my $output_absolute = File::Spec->rel2abs($output);
    fail() if $upstream eq $output_absolute || index($output_absolute, "$upstream/") == 0;
    $output = safe_directory($output, 1);
    fail() if (stat($output))[4] != $<;
    for my $name ('mozconfig.operational', 'firefox-build.operational', 'metadata.json',
                  'path-tiny-source.sha256', 'atomic-spew-hardlink.json') {
        fail() if -e "$output/$name" || -l "$output/$name";
    }
    chdir($upstream) or fail();
    unshift @INC, "$upstream/rbm/lib";
    require RBM;
    require Path::Tiny;

    # Match the ordinary RBM build entry, not a no_build_id or shadow-source target.
    RBM::load_config("$upstream/rbm.conf");
    $RBM::config->{rbmdir} = "$upstream/rbm"; # Same FindBin value as rbm/rbm.
    RBM::set_default_env();
    $RBM::config->{run}{target} = ['alpha', 'mullvadbrowser-windows-x86_64', 'pgo-generate'];
    $RBM::config->{step} = 'build';
    RBM::load_system_config('firefox');
    RBM::load_local_config('firefox');
    RBM::load_modules_config('firefox');
    $RBM::config->{run}{args} = [];
    RBM::valid_project('firefox');

    # Deny cold-input side effects. Valid warm metadata still uses native APIs.
    my $original_git = \&RBM::git_clone_fetch_chdir;
    my $original_inputs = \&RBM::input_files;
    local *RBM::git_clone_fetch_chdir = sub {
        my ($project, $options) = @_;
        my $clone_root = RBM::rbm_path(RBM::project_config($project, 'git_clone_dir', $options));
        my $clone = File::Spec->catdir($clone_root, $project);
        fail() unless -d $clone && !-l $clone;
        my $cwd = getcwd();
        chdir($clone) or fail();
        my $fetch = RBM::git_need_fetch($project, $options);
        chdir($cwd) or fail();
        fail() if $fetch;
        return $original_git->(@_);
    };
    local *RBM::hg_clone_fetch_chdir = sub { fail(); };
    local *RBM::urlget = sub { fail(); };
    local *RBM::build_pkg = sub { fail(); };
    local *RBM::build_run = sub { fail(); };
    local *RBM::input_files = sub {
        fail() unless $_[0] eq 'getfnames' || $_[0] eq 'getfids' || $_[0] eq 'input_files_id';
        return $original_inputs->(@_);
    };

    my $num = RBM::project_config('firefox', 'num_procs');
    fail() unless defined($num) && !ref($num) && $num =~ /^[1-9]\d{0,5}$/;
    my $inputs = RBM::project_config('firefox', 'input_files');
    fail() unless ref($inputs) eq 'ARRAY';
    my @mozconfigs = grep { ref($_) eq 'HASH' && defined($_->{filename})
                            && $_->{filename} eq 'mozconfig' } @$inputs;
    fail() unless @mozconfigs == 1 && defined($mozconfigs[0]->{content});
    $mozconfig = RBM::project_config('firefox', 'content',
                                    { pkg_type => 'build', %{$mozconfigs[0]} });
    $build = RBM::project_config('firefox', 'build', { pkg_type => 'build' });
    fail() unless defined($mozconfig) && !ref($mozconfig) && length($mozconfig)
                   && defined($build) && !ref($build) && length($build);
    fail() unless length(encode('UTF-8', $mozconfig)) <= 1024 * 1024
                   && length(encode('UTF-8', $build)) <= 1024 * 1024;

    # Use ACTUAL configured operational and normalized-four content, not a toy.
    # This invokes only the pinned primitive, never the whole dependency link path.
    my $normalized_mozconfig = RBM::project_config('firefox', 'content',
                            { pkg_type => 'build', %{$mozconfigs[0]}, num_procs => 4 });
    fail() unless defined($normalized_mozconfig) && !ref($normalized_mozconfig)
                   && length($normalized_mozconfig)
                   && length(encode('UTF-8', $normalized_mozconfig)) <= 1024 * 1024;
    my $operational_bytes = encode('UTF-8', $mozconfig);
    my $normalized_bytes = encode('UTF-8', $normalized_mozconfig);
    my $scratch = tempdir('path-tiny-XXXXXX', DIR => $output, CLEANUP => 1);
    my $original = Path::Tiny::path("$scratch/original");
    my $linked = "$scratch/staged";
    $original->spew_utf8($mozconfig);
    my @copied = RBM::recursive_copy("$original", 'staged', $scratch, 'link');
    fail() unless @copied == 1 && $copied[0] eq 'staged';
    my @before = stat("$original");
    my @staged = stat($linked);
    fail() unless $before[0] == $staged[0] && $before[1] == $staged[1];
    $original->spew_utf8($normalized_mozconfig);
    my $original_bytes = $original->slurp_raw;
    my $linked_bytes = Path::Tiny::path($linked)->slurp_raw;
    my @after = stat("$original");
    my @linked_after = stat($linked);
    fail() unless $original_bytes eq $normalized_bytes && $linked_bytes eq $operational_bytes
                   && $after[0] == $linked_after[0] && $after[1] != $linked_after[1]
                   && $linked_after[1] == $staged[1];
    my $version = "$Path::Tiny::VERSION";
    fail() unless $version =~ /^\d+\.\d+(?:_\d+)?$/ && length($version) <= 32;
    my $module = $INC{'Path/Tiny.pm'};
    fail() unless defined($module) && -f $module && -s $module <= 1024 * 1024;
    my $module_sha256 = sha256_hex(Path::Tiny::path($module)->slurp_raw);
    $tiny_digest = $module_sha256 . "\n";
    my $logical = logical_cpu_count();
    $metadata = {schema => 1, num_procs => 0 + $num, logical_cpu_count => 0 + $logical,
                 affinity => current_affinity(), path_tiny_version => $version,
                 path_tiny_source_sha256 => $module_sha256,
                 atomic_spew_hardlink_verified => JSON::PP::true};
    $atomic_evidence = {operational_bytes => length($operational_bytes),
                       normalized_bytes => length($normalized_bytes),
                       hardlink_same_inode_before => JSON::PP::true,
                       atomic_inode_replaced => JSON::PP::true,
                       staged_operational_bytes_preserved => JSON::PP::true,
                       original_after_sha256 => sha256_hex($original_bytes),
                       staged_after_sha256 => sha256_hex($linked_bytes)};
    1;
};
open(STDOUT, '>&', $saved_stdout) or fail();
open(STDERR, '>&', $saved_stderr) or fail();
close($saved_stdout) or fail();
close($saved_stderr) or fail();
if (!$ok) {
    print STDERR "PGO resource metadata rendering failed; inputs must be warm and verified.\n";
    exit 1;
}
my $written = eval {
    write_public($output, 'mozconfig.operational', encode('UTF-8', $mozconfig));
    write_public($output, 'firefox-build.operational', encode('UTF-8', $build));
    write_public($output, 'path-tiny-source.sha256', $tiny_digest);
    write_public($output, 'atomic-spew-hardlink.json',
                 JSON::PP->new->canonical->encode($atomic_evidence) . "\n");
    # Metadata is last: a partial render must never look like a successful case.
    write_public($output, 'metadata.json', JSON::PP->new->canonical->encode($metadata) . "\n");
    1;
};
if (!$written) {
    print STDERR "PGO resource metadata output could not be saved safely.\n";
    exit 1;
}
exit 0;
