#!/usr/bin/perl -w -T

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_names.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("meta");

use Mail::SpamAssassin;

use vars qw( %rules %scores $perl_path);

# "parse-rules-for-masses" requires Data::Dumper
use constant HAS_DATADUMPER => eval 'use Data::Dumper; 1;';

use Test::More;

plan skip_all => "Needs Data::Dumper" unless HAS_DATADUMPER;
plan skip_all => "Tests don't work on Windows" if $^O =~ /^(mswin|dos|os2)/i;
plan tests => 2;

# meta failures
my $meta_dependency_disabled = 0;
my $meta_dependency_nonexistent = 0;

for (my $scoreset = 0; $scoreset < 4; $scoreset++) {
  my $output = "log/rules-$scoreset.pl";
  unlink $output || die;
  %rules = ();
  %scores = ();
  if (untaint_system("$perl_path $prefix/build/parse-rules-for-masses -o $output -d \"$prefix/rules\" -s $scoreset -x")) {
    warn "parse-rules-for-masses failed!";
  }
  eval {
    require "log/rules-$scoreset.pl";
  };
  if ($@) {
    warn "log/rules-$scoreset.pl is unparseable: $@";
    warn "giving up on test.";
    ok(1);
    ok(1);
    exit;
  }

  while (my ($name, $info) = each %rules) {
    next if ($name eq '_scoreset');
    my $type = $info->{type} || "unknown";
    # look at meta rules that are not disabled
    if ($type eq "meta" && ($name =~ /^__/ || $info->{score} != 0)) {
      if ($info->{depends}) {
	for my $depend (@{ $info->{depends} }) {
	  if (!exists $rules{$depend}) {
	    warn "$name depends on $depend which is nonexistent\n";
	    $meta_dependency_nonexistent = 1;
	    next;
	  }

	  # if dependency is a predicate, it'll run
	  next if $depend =~ /^__/;

	  # if dependency has a non-zero score, it'll run
	  next if (defined $rules{$depend}->{score} &&
		   $rules{$depend}->{score} != 0);

          # ignore "tflags net" and "tflags learn" rules -- it is OK
          # for those to have zero scores in some scoresets, for obvious
          # reasons.
          next if (defined $rules{$depend}->{tflags} &&
                  $rules{$depend}->{tflags} =~ /\b(?:net|learn)\b/);

	  warn "$name depends on $depend with 0 score in set $scoreset\n";
	  $meta_dependency_disabled = 1;
	}
      }
    }
  }
}

ok(!$meta_dependency_disabled);
ok(!$meta_dependency_nonexistent);
