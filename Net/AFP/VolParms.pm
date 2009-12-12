package Net::AFP::VolParms;

use Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(kFPVolAttributeBit kFPVolSignatureBit kFPVolCreateDateBit
				 kFPVolModDateBit kFPVolBackupDateBit kFPVolIDBit
				 kFPVolBytesFreeBit kFPVolBytesTotalBit kFPVolNameBit
				 kFPVolExtBytesFreeBit kFPVolExtBytesTotalBit
				 kFPVolBlockSizeBit kFPBadVolBitmap kFPBadVolPre222Bitmap);

=head1 NAME

Net::AFP::VolParms - Volume parameter arguments

=head1 DESCRIPTION

The following attributes are used for calls like
L<Net::AFP::Connection/FPOpenVol> and
L<Net::AFP::Connection/FPGetVolParms>.

=over

=item kFPVolAttributeBit

Volume attributes. See L<Net::AFP::VolAttrs/Attribute Flags> for details.

=cut
use constant kFPVolAttributeBit		=> 0x0001;
=item kFPVolSignatureBit

The volume signature identifies the volume type (flat, fixed Directory ID,
or variable Directory ID). For details, see the section "Volume Types."

=cut
use constant kFPVolSignatureBit		=> 0x0002;
=item kFPVolCreateDateBit

The date the server created the volume. This parameter cannot be modified
by an AFP client.

=cut
use constant kFPVolCreateDateBit	=> 0x0004;
=item kFPVolModDateBit

Updated by the server each time anything on the volume is modified. This parameter cannot be modified by an AFP client.

=cut
use constant kFPVolModDateBit		=> 0x0008;
=item kFPVolBackupDateBit

Set by a backup program each time the volume¿s contents are backed up.
When a volume is created, the Backup Date is set to 0x80000000 (the
earliest representable date-time value).

=cut
use constant kFPVolBackupDateBit	=> 0x0010;
=item kFPVolIDBit

For each session between the server and an AFP client, the server assigns
a Volume ID to each of its volumes. This value is unique among the volumes
of a given server for that session.

=cut
use constant kFPVolIDBit			=> 0x0020;
=item kFPVolBytesFreeBit

Total bytes free on volumes less than 4 GB in size. If a volume is more
than 4 GB, the Bytes Free parameters may not reflect the actual value. In
any case, Extended Bytes Free always reflects the correct value. This
value is maintained by the server and cannot be modified by an AFP client.

=cut
use constant kFPVolBytesFreeBit		=> 0x0040;
=item kFPVolBytesTotalBit

Total bytes on volumes less than 4 GB in size. If a volume is more than
4 GB, the Bytes Total parameter may not reflect the actual value. In any
case, Extended Bytes Total always reflects the correct value. This value
is maintained by the server and cannot be modified by an AFP client.

=cut
use constant kFPVolBytesTotalBit	=> 0x0080;
=item kFPVolNameBit

The volume name identifies a server volume to an AFP client user, so it
must be unique among all volumes managed by the server. All eight-bit
ASCII characters, except null (0x00) and colon (0x3A), are permitted in
a volume name. This name is not used directly to specify files and
directories on the volume. Instead, the AFP client sends an AFP command
to obtain a particular volume identifier, which it then uses when
sending subsequent AFP commands. For more information, see "Designating
a Path to a CNode".

=cut
use constant kFPVolNameBit			=> 0x0100;
=item kFPVolExtBytesFreeBit

Total bytes free on this volume. This value is maintained by the server
and cannot be modified by an AFP client

=cut
use constant kFPVolExtBytesFreeBit	=> 0x0200;
=item kFPVolExtBytesTotalBit

Total bytes on this volume. This value is maintained by the server and
cannot be modified by an AFP client.

=cut
use constant kFPVolExtBytesTotalBit	=> 0x0400;
=item kFPVolBlockSizeBit

The block allocation size.

=cut
use constant kFPVolBlockSizeBit		=> 0x0800;
use constant kFPBadVolBitmap		=> 0xF000;
use constant kFPBadVolPre222Bitmap	=> 0xFE00;

=back

=cut
1;
# vim: ts=4
