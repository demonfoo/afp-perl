#!/usr/bin/env perl

# imports {{{1
use lib qw(/home/demon/libafp);
use Net::AFP::ACL;
use File::ExtAttr qw(:all);
use Getopt::Long;
use Encode;
use POSIX qw(EINVAL ENOENT EACCES EBADF EPERM EOPNOTSUPP);
sub ENODATA() { return 61; }	# need this error constant for extended
								# attribute operations

use strict;
use warnings;
# }}}1

# define constants {{{1
use constant XATTR_NAME		=> 'afp_acl';
use constant XATTR_NS		=> 'system';
# }}}1

# Take a binary packed ACL representation and generate a structured
# representation for us to twiddle.
sub parse_xattr($) { # {{{1
	my($raw_acl) = @_;

	my($acl_flags, @acl_parts) = unpack('LS/(LS/aLL)', $raw_acl);
	
	my @entries;
	while (scalar(@acl_parts) > 0) {
		my $entry = {};
		$$entry{'Bitmap'} = shift(@acl_parts);
		$$entry{'UTF8Name'} = shift(@acl_parts);
		$$entry{'ace_flags'} = shift(@acl_parts);
		$$entry{'ace_rights'} = shift(@acl_parts);
		push(@entries, $entry);
	}

	return($acl_flags, [@entries]);
} # }}}1

# Take a structured access control list and pack it into a serialized binary
# form that we can then jam into the extended attribute for the FUSE
# implementation to push on to the AFP server.
sub assemble_xattr($$) { # {{{1
	my($acl_flags, $acl_ace) = @_;

	my @acl_parts;
	foreach my $ace (@$acl_ace) {
		push(@acl_parts, pack('LS/aLL',
				@$ace{'Bitmap', 'UTF8Name', 'ace_flags', 'ace_rights'}));
	}
	return pack('NS/(a*)', $acl_flags, @acl_parts);	
} # }}}1

# Association of the rights bits with names (and flags in case of directory
# or non-directory specific rights).
my @ace_rights_info = ( # {{{1
	{
	  'name'	=> 'read',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_READ_DATA,
	  'for_dir'	=> 0,
	},
	{
	  'name'	=> 'list',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_LIST_DIRECTORY,
	  'for_dir'	=> 1,
	},
	{
	  'name'	=> 'write',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_WRITE_DATA,
	  'for_dir'	=> 0,
	},
	{
	  'name'	=> 'add_file',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_ADD_FILE,
	  'for_dir'	=> 1,
	},
	{
	  'name'	=> 'execute',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_EXECUTE,
	  'for_dir'	=> 0,
	},
	{
	  'name'	=> 'search',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_SEARCH,
	  'for_dir'	=> 1,
	},
	{
	  'name'	=> 'delete',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_DELETE,
	},
	{
	  'name'	=> 'append',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_APPEND_DATA,
	  'for_dir'	=> 0,
	},
	{
	  'name'	=> 'add_subdirectory',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_ADD_SUBDIRECTORY,
	  'for_dir'	=> 1,
	},
	{
	  'name'	=> 'delete_child',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_DELETE_CHILD,
	},
	{
	  'name'	=> 'readattr',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_READ_ATTRIBUTES,
	},
	{
	  'name'	=> 'writeattr',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_WRITE_ATTRIBUTES,
	},
	{
	  'name'	=> 'readextattr',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_READ_EXTATTRIBUTES,
	},
	{
	  'name'	=> 'writeextattr',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_WRITE_EXTATTRIBUTES,
	},
	{
	  'name'	=> 'readsecurity',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_READ_SECURITY,
	},
	{
	  'name'	=> 'writesecurity',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_WRITE_SECURITY,
	},
	{
	  'name'	=> 'chown',
	  'value'	=> Net::AFP::ACL::KAUTH_VNODE_CHANGE_OWNER,
	},
); # }}}1

# Assemble the rights descriptions into a hash by name.
my %ace_rights_byname = map { $$_{'name'}, $_ } @ace_rights_info;

# Error strings for the errors that we might get...
my %errors = ( # {{{1
			   &EINVAL		=> 'User/group not found',
			   &ENOENT		=> 'No such file or directory',
			   &EACCES		=> 'Permission denied',
			   &EBADF		=> 'Unknown error occurred',
			   &EPERM		=> 'Operation not permitted',
			   &ENODATA		=> 'AFP server does not support ACLs',
			   &EOPNOTSUPP	=> 'AFP server does not support ACLs',
             ); # }}}1

# Turn a textual ACE description into a data structure for later packing.
sub make_ace { # {{{1
	my ($line) = @_;

	my $ace = {};
	my @parts = split(/\s+/, $line);
	my $about = shift(@parts);
	my @about_parts = split(/:/, $about);
	$$ace{'Bitmap'} = 0;
	if ($about_parts[0] eq 'user') {
		$$ace{'Bitmap'} = Net::AFP::ACL::kFileSec_UUID;
		shift(@about_parts);
	} elsif ($about_parts[0] eq 'group') {
		$$ace{'Bitmap'} = Net::AFP::ACL::kFileSec_GRPUUID;
		shift(@about_parts);
	}
	$$ace{'UTF8Name'} = decode_utf8($about_parts[0]);

	my $kind = shift(@parts);
	$$ace{'ace_flags'} = 0;
	if ($kind eq 'allow') {
		$$ace{'ace_flags'} = Net::AFP::ACL::KAUTH_ACE_PERMIT;
	} elsif ($kind eq 'deny') {
		$$ace{'ace_flags'} = Net::AFP::ACL::KAUTH_ACE_DENY;
	} else {
		die("ACL kind " . $kind . " is not valid");
	}

	my $rights = shift(@parts);
	$$ace{'ace_rights'} = 0;
	foreach my $right (split(/\s*,\s*/, $rights)) {
		die("Access right " . $right . " is not valid")
				unless exists $ace_rights_byname{$right};
		$$ace{'ace_rights'} |= $ace_rights_byname{$right}->{'value'};
	}

	return $ace;
} # }}}1

my($remove, $add, @insert, @replace, $clear);

GetOptions('remove=s'		=> \$remove,
		   'add=s'			=> \$add,
		   'insert=s{2}'	=> \@insert,
		   'replace=s{2}'	=> \@replace,
		   'clear'			=> \$clear);

if (defined $remove) { # {{{1
	my $ace;
	my $offset;
	# If the value given is a number, then we can just delete by number.
	# Otherwise, assume it's a textual ACE description for us to parse.
	if ($remove =~ /^\d+$/) {
		$offset = $remove;
	} else {
		$ace = make_ace($remove);
	}

	foreach my $file (@ARGV) { # {{{2
		# Get the ACL for the file via the magic extended attribute, and if
		# one is available, go ahead and parse it.
		my $raw_acl = getfattr($file, XATTR_NAME, { 'namespace' => XATTR_NS });
		next unless defined $raw_acl;
		my($acl_flags, $acl) = parse_xattr($raw_acl);
		if (defined $offset) {
			# Remove the ACE by number.
			die() unless (($offset >= 0) && ($offset <= $#$acl));
			@$acl = @$acl[0 .. ($offset - 1), ($offset + 1) .. $#$acl];
		} else {
			# Search the file's ACEs for one with the same subject and type.
			# If we find one or more ACEs that match, mask off the bits
			# for the rights to be removed.
			foreach my $entry (@$acl) {
				next unless $$ace{'UTF8Name'} eq $$entry{'UTF8Name'};
				if ($$ace{'Bitmap'} != 0) {
					next unless $$ace{'Bitmap'} == $$entry{'Bitmap'};
				}
				next unless $$ace{'ace_flags'} ==
						($$entry{'ace_flags'} & Net::AFP::ACL::KAUTH_ACE_KINDMASK);
				$$entry{'ace_rights'} &= ~$$ace{'ace_rights'};
			}
			# Prune out any empty ACEs from the list.
			for (my $i = $#$acl; $i >= 0; $i--) {
				if ($$acl[$i]->{'ace_rights'} == 0) {
					@$acl = @$acl[0 .. ($i - 1), ($i + 1) .. $#$acl];
				}
			}
		}
		# Repack the ACL, and update the extended attribute.
		my $new_rawacl = assemble_xattr($acl_flags, $acl);
		my $rv = setfattr($file, XATTR_NAME, $new_rawacl,
				{ 'namespace' => XATTR_NS });
		unless ($rv) {
			print "Error while updating ACL on \"", $file, "\": ",
					$errors{int($!)},"\n";
		}
	} # }}}2
} # }}}1
elsif (defined $add) { # {{{1
	# Translate the textual ACE into structured form.
	my $ace = make_ace($add);

	foreach my $file (@ARGV) { # {{{2
		# Fetch the ACL, if there is one; if not, just make an empty array
		# ref that we can stick the new ACE into.
		my $raw_acl = getfattr($file, XATTR_NAME, { 'namespace' => XATTR_NS });
		my($acl, $acl_flags) = ([], 0);
		if (defined $raw_acl) {
			($acl_flags, $acl) = parse_xattr($raw_acl);
		}

		my $first_allow;
		my $non_canonical;
		my $entry_matches;
		for (my $i = 0; $i <= $#$acl; $i++) { # {{{3
			# Look for the first 'allow' ACE; once one's found, if there is
			# a 'deny' ACE after it, the ACL is not in "canonical" order,
			# and we can't do a normal 'add'.
			my $entry = $$acl[$i];
			my $acl_kind = $$entry{'ace_flags'} &
					Net::AFP::ACL::KAUTH_ACE_KINDMASK;
			if ($acl_kind == Net::AFP::ACL::KAUTH_ACE_PERMIT) {
				unless (defined $first_allow) {
					$first_allow = $i;
				}
			} else {
				if (defined $first_allow) {
					$non_canonical = 1;
					last;
				}
			}

			# See if this entry matches the subject and type of the
			# new ACE.
			if ($$entry{'UTF8Name'} eq $$ace{'UTF8Name'} &&
					$$entry{'ace_flags'} == $$ace{'ace_flags'}) {
				if ($$ace{'Bitmap'} != 0) {
					next unless $$ace{'Bitmap'} == $$entry{'Bitmap'};
				}
				$entry_matches = $entry;
			}
		} # }}}3
		if ($non_canonical) {
			print "The file \"", $file, "\" does not have an ACL in canonical order; use --insert instead.\n";
			next;
		}

		if (defined $entry_matches) { # {{{3
			# Just add the additional rights to the preexisting ACE with the
			# matching subject and type.
			$$entry_matches{'ace_rights'} |= $$ace{'ace_rights'};
		} else {
			# Add the ACE to the list, at the beginning of the appropriate
			# grouping.
			my $offset = 0;
			my $acl_kind = $$ace{'ace_flags'} &
					Net::AFP::ACL::KAUTH_ACE_KINDMASK;
			if ($acl_kind == Net::AFP::ACL::KAUTH_ACE_PERMIT) {
				if (defined($first_allow)) {
					$offset = $first_allow;
				} else {
					$offset = scalar(@$acl);
				}
			}
			@$acl = (@$acl[0 .. ($offset - 1)], $ace, @$acl[$offset .. $#$acl]);
		} # }}}3

		# Repack the ACL, and push it back out via the extended attribute.
		my $new_rawacl = assemble_xattr($acl_flags, $acl);
		my $rv = setfattr($file, XATTR_NAME, $new_rawacl,
				{ 'namespace' => XATTR_NS });
		unless ($rv) {
			print "Error while updating ACL on \"", $file, "\": ",
					$errors{int($!)},"\n";
		}
	} # }}}2
} # }}}1
elsif (scalar(@insert)) { # {{{1
	# Parse the textual ACE, and get the offset to add the new one at.
	my $ace = make_ace($insert[1]);
	my $offset = int($insert[0]);
	die() unless $offset >= 0;

	foreach my $file (@ARGV) { # {{{2
		# Get the file's ACL. Parse it if there is one; if not, just set
		# an empty array ref, so that we can try to add the entry.
		my $raw_acl = getfattr($file, XATTR_NAME, { 'namespace' => XATTR_NS });
		my($acl, $acl_flags) = ([], 0);
		if (defined $raw_acl) {
			($acl_flags, $acl) = parse_xattr($raw_acl);
		}
		if ($offset > scalar(@$acl)) {
			print "Cannot add ACL entry at offset ", $offset, " for file \"",
					$file, "\"; offset too large\n";
			next;
		}
		# Use array slicing tricks to add the new entry to the list.
		@$acl = (@$acl[0 .. ($offset - 1)], $ace, @$acl[$offset .. $#$acl]);

		# Repack the ACL, and push it back out via the extended attribute.
		my $new_rawacl = assemble_xattr($acl_flags, $acl);
		my $rv = setfattr($file, XATTR_NAME, $new_rawacl,
				{ 'namespace' => XATTR_NS });
		unless ($rv) {
			print "Error while updating ACL on \"", $file, "\": ",
					$errors{int($!)},"\n";
		}
	} # }}}2
} # }}}1
elsif (scalar(@replace)) { # {{{1
	# Parse the textual ACE, and the offset of the ACE to replace.
	my $ace = make_ace($replace[1]);
	my $offset = int($replace[0]);
	die() unless $offset >= 0;

	foreach my $file (@ARGV) { # {{{2
		# Get the ACL for the file. If it's present, parse it out; otherwise,
		# just use an empty array ref.
		my $raw_acl = getfattr($file, XATTR_NAME, { 'namespace' => XATTR_NS });
		my($acl, $acl_flags) = ([], 0);
		if (defined $raw_acl) {
			($acl_flags, $acl) = parse_xattr($raw_acl);
		}
		# If the offset points to an entry that doesn't exist, then give up
		# and move on to the next file.
		if ($offset > scalar($#$acl)) {
			print "Cannot replace ACL entry at offset ", $offset,
					" for file \"", $file, "\"; offset too large\n";
			next;
		}
		# Replace the indicated ACE.
		$$acl[$offset] = $ace;

		# Repack the ACL, and push it back out to the extended attribute.
		my $new_rawacl = assemble_xattr($acl_flags, $acl);
		my $rv = setfattr($file, XATTR_NAME, $new_rawacl,
				{ 'namespace' => XATTR_NS });
		unless ($rv) {
			print "Error while updating ACL on \"", $file, "\": ",
					$errors{int($!)},"\n";
		}
	} # }}}2
} # }}}1
elsif (defined $clear) { # {{{1
	foreach my $file (@ARGV) {
		# Remove the extended attribute. The FUSE code knows that this means
		# to delete the ACL in its entirety.
		my $rv = delfattr($file, XATTR_NAME, { 'namespace' => XATTR_NS });
		unless ($rv) {
			print "Error while updating ACL on \"", $file, "\": ",
					$errors{int($!)},"\n";
		}
	}
} # }}}1
else { # {{{1
	foreach my $file (@ARGV) {
		# Get the ACL for the file, and break it out into a data structure.
		my $raw_acl = getfattr($file, XATTR_NAME, { 'namespace' => XATTR_NS });
		my($acl, $acl_flags) = ([], 0);
		if (defined $raw_acl) {
			($acl_flags, $acl) = parse_xattr($raw_acl);
		}

		# If multiple files were named, name the file that the ACL goes with.
		if (scalar(@ARGV) > 1) {
			print "ACL for file \"", $file, "\":\n";
		}

		for (my $i = 0; $i < scalar(@$acl); $i++) { # {{{2
			my $entry = $$acl[$i];

			# What sort of object is this entry about?
			my $idtype;
			if ($$entry{'Bitmap'} == Net::AFP::ACL::kFileSec_UUID) {
				$idtype = 'user';
			} elsif ($$entry{'Bitmap'} == Net::AFP::ACL::kFileSec_GRPUUID) {
				$idtype = 'group';
			}
			my $acl_kind = $$entry{'ace_flags'} & Net::AFP::ACL::KAUTH_ACE_KINDMASK;
			# What kind of action does it specify?
			my $kind = 'unknown';
			if ($acl_kind == Net::AFP::ACL::KAUTH_ACE_PERMIT) {
				$kind = 'allow';
			} elsif ($acl_kind == Net::AFP::ACL::KAUTH_ACE_DENY) {
				$kind = 'deny';
			}

			# What rights are conferred/retracted?
			my @actions = ();
			my $rights = $$entry{'ace_rights'};
			foreach my $rinfo (@ace_rights_info) {
				next unless $rights & $$rinfo{'value'};
				if (exists $$rinfo{'for_dir'}) {
					my $is_dir = -d $file;
					next unless (($is_dir && $$rinfo{'for_dir'}) ||
							(!$is_dir && !$$rinfo{'for_dir'}));
				}
				push(@actions, $$rinfo{'name'});
			}
			# Print out the entry.
			printf(" \%d: \%s:\%s \%s \%s\n", $i, $idtype,
					$$entry{'UTF8Name'}, $kind, join(',', @actions));
		} # }}}2
	}
} # }}}1

# vim: ts=4 fdm=marker
