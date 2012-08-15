package Net::AFP::Result;

use Exporter qw(import);

our @EXPORT = qw(kFPNoErr kASPBadVersNum kASPBufTooSmall kFPNoMoreSessions
                 kASPNoServers kASPParamErr kASPServerBusy kASPSessClosed
                 kFPAccessDenied kASPSizeErr kASPTooManyClients kASPNoAck
                 kFPAuthContinue kFPBadUAM kFPBadVersNum kFPBitmapErr
                 kFPCantMove kFPDenyConflict kFPDirNotEmpty kFPDiskFull
                 kFPEOFErr kFPFileBusy kFPFlatVol kFPItemNotFound kFPLockErr
                 kFPMiscErr kFPNoMoreLocks kFPNoServer kFPObjectExists
                 kFPObjectNotFound kFPParamErr kFPRangeNotLocked
                 kFPRangeOverlap kFPSessClosed kFPUserNotAuth
                 kFPCallNotSupported kFPObjectTypeErr kFPTooManyFilesOpen
                 kFPServerGoingDown kFPCantRename kFPDirNotFound
                 kFPIconTypeErr kFPVolLocked kFPObjectLocked
                 kFPContainsSharedErr kFPIDNotFound kPIDExists
                 kFPCatalogChanged kFPSameObjectErr kFPBadIDErr
                 kFPPwdSameErr kFPPwdTooShortErr kFPPwdExpiredErr
                 kFPInsideSharedErr kFPInsideTrashErr kFPPwdNeedsChangeErr
                 kFPPwdPolicyErr kFPDiskQuotaExceeded afp_strerror);

=head1 NAME

Net::AFP::Result - Perl module containing AFP error symbol information

=head1 SYNOPSIS

This package contains symbol defintions for all known AFP error condition
codes, as well as a helper function to transform an error code into its
plain English equivalent.

=head1 ERROR SYMBOLS

=over

=item kFPNoErr

No error occurred (success).

=cut
use constant kFPNoErr               => 0;
=item kASPBadVersNum

=cut
use constant kASPBadVersNum         => -1066;
=item kASPBufTooSmall

=cut
use constant kASPBufTooSmall        => -1067;
=item kFPNoMoreSessions

Server cannot handle additional sessions.

This error usually indicates that the server limits the maximum number of
concurrent clients, and that this maximum number would be exceeded by
honoring this login request.

=cut
use constant kFPNoMoreSessions      => -1068;
=item kASPNoServers

=cut
use constant kASPNoServers          => -1069;
=item kASPParamErr

=cut
use constant kASPParamErr           => -1070;
=item kASPServerBusy

=cut
use constant kASPServerBusy         => -1071;
=item kASPSessClosed

ASP session closed.

=cut
use constant kASPSessClosed         => -1072;
=item kASPSizeErr

=cut
use constant kASPSizeErr            => -1073;
=item kASPTooManyClients

=cut
use constant kASPTooManyClients     => -1074;
=item kASPNoAck

=cut
use constant kASPNoAck              => -1075;
=item kFPAccessDenied

User does not have the access privileges required to use the command.

=cut
use constant kFPAccessDenied        => -5000;
=item kFPAuthContinue

Authentication is not yet complete.

=cut
use constant kFPAuthContinue        => -5001;
=item kFPBadUAM

Specified UAM is unknown.

=cut
use constant kFPBadUAM              => -5002;
=item kFPBadVersNum

Server does not support the specified AFP version.

=cut
use constant kFPBadVersNum          => -5003;
=item kFPBitmapErr

Attempt was made to get or set a parameter that cannot be obtained or set
with this command, or a required bitmap is null.

=cut
use constant kFPBitmapErr           => -5004;
=item kFPCantMove

Attempt was made to move a directory into one of its descendent directories.

=cut
use constant kFPCantMove            => -5005;
=item kFPDenyConflict

Specified fork cannot be opened because of a deny modes conflict.

=cut
use constant kFPDenyConflict        => -5006;
=item kFPDirNotEmpty

Directory is not empty.

=cut
use constant kFPDirNotEmpty         => -5007;
=item kFPDiskFull

No more space exists on the volume.

=cut
use constant kFPDiskFull            => -5008;
=item kFPEOFErr

No more matches or end of fork reached.

=cut
use constant kFPEOFErr              => -5009;
=item kFPFileBusy

When attempting a hard create, the file already exists and is open.

=cut
use constant kFPFileBusy            => -5010;
=item kFPFlatVol

Volume is flat and does not support directories.

=cut
use constant kFPFlatVol             => -5011;
=item kFPItemNotFound

Specified APPL mapping, comment, or icon was not found in the Desktop
database; specified ID is unknown.

=cut
use constant kFPItemNotFound        => -5012;
=item kFPLockErr

Some or all of the requested range is locked by another user; a lock range
conflict exists.

=cut
use constant kFPLockErr             => -5013;
=item kFPMiscErr

Non-AFP error occurred.

=cut
use constant kFPMiscErr             => -5014;
=item kFPNoMoreLocks

Server's maximum lock count has been reached.

=cut
use constant kFPNoMoreLocks         => -5015;
=item kFPNoServer

Server is not responding.

=cut
use constant kFPNoServer            => -5016;
=item kFPObjectExists

File or directory already exists.

=cut
use constant kFPObjectExists        => -5017;
=item kFPObjectNotFound

Input parameters do not point to an existing directory, file, or volume.

=cut
use constant kFPObjectNotFound      => -5018;
=item kFPParamErr

Session reference number, Desktop database reference number, open fork
reference number, Volume ID, Directory ID, File ID, Group ID, or
subfunction is unknown; byte range starts before byte zero; pathname is
invalid; pathname type is unknown; user name is null, exceeds the UAM's
user name length limit, or does not exist, MaxReplySize is too small to
hold a single offspring structure, ThisUser bit is not set, authentication
failed for an undisclosed reason, specified user is unknown or the
account has been disabled due to too many login attempts; ReqCount or
Offset is negative; NewLineMask is invalid.

=cut
use constant kFPParamErr            => -5019;
=item kFPRangeNotLocked

Attempt to unlock a range that is locked by another user or that is not
locked at all.

=cut
use constant kFPRangeNotLocked      => -5020;
=item kFPRangeOverlap

User tried to lock some or all of a range that the user has already
locked.

=cut
use constant kFPRangeOverlap        => -5021;
=item kFPSessClosed

Session is closed.

=cut
use constant kFPSessClosed          => -5022;
=item kFPUserNotAuth

UAM failed (the specified old password doesn't match); no user is logged
in yet for the specified session; authentication failed; password is
incorrect.

=cut
use constant kFPUserNotAuth         => -5023;
=item kFPCallNotSupported

Server does not support this command.

=cut
use constant kFPCallNotSupported    => -5024;
=item kFPObjectTypeErr

Input parameters point to the wrong type of object.

=cut
use constant kFPObjectTypeErr       => -5025;
=item kFPTooManyFilesOpen

Server cannot open another fork.

=cut
use constant kFPTooManyFilesOpen    => -5026;
=item kFPServerGoingDown

Server is shutting down.

=cut
use constant kFPServerGoingDown     => -5027;
=item kFPCantRename

Attempt was made to rename a volume or root directory.

=cut
use constant kFPCantRename          => -5028;
=item kFPDirNotFound

Input parameters do not point to an existing directory.

=cut
use constant kFPDirNotFound         => -5029;
=item kFPIconTypeError

New icon's size is different from the size of the existing icon.

=cut
use constant kFPIconTypeError       => -5030;
=item kFPVolLocked

Volume is Read Only.

=cut
use constant kFPVolLocked           => -5031;
=item kFPObjectLocked

File or directory is marked DeleteInhibit; directory being moved, renamed,
or moved and renamed is marked RenameInhibit; file being moved and renamed
is marked RenameInhibit; attempt was made to open a file for writing that
is marked WriteInhibit; attempt was made to rename a file or directory that
is marked RenameInhibit.

=cut
use constant kFPObjectLocked        => -5032;
=item kFPContainsSharedErr

Directory contains a share point.

=cut
use constant kFPContainsSharedErr   => -5033;
=item kFPIDNotFound

File ID was not found. (No file thread exists.)

=cut
use constant kFPIDNotFound          => -5034;   # AFP 2.1
=item kFPIDExists

File already has a File ID.

=cut
use constant kFPIDExists            => -5035;   # AFP 2.1
=item kFPDiffVolErr

Wrong volume.

=cut
use constant kFPDiffVolErr          => -5036;   # AFP 2.1
=item kFPCatalogChanged

Catalog has changed.

=cut
use constant kFPCatalogChanged      => -5037;   # AFP 2.1
=item kFPSameObjectErr

Two objects that should be different are the same object.

=cut
use constant kFPSameObjectErr       => -5038;   # AFP 2.1
=item kFPBadIDErr

File ID is not valid.

=cut
use constant kFPBadIDErr            => -5039;   # AFP 2.1
=item kFPPwdSameErr

User attempted to change his or her password to the same password that
is currently set.

=cut
use constant kFPPwdSameErr          => -5040;   # AFP 2.1
=item kFPPwdTooShortErr

User password is shorter than the server's minimum password length, or
user attempted to change password to a password that is shorter than
the server's minimum password length.

=cut
use constant kFPPwdTooShortErr      => -5041;   # AFP 2.1
=item kFPPwdExpiredErr

User's password has expired.

=cut
use constant kFPPwdExpiredErr       => -5042;   # AFP 2.1
=item kFPInsideSharedErr

Directory being moved contains a share point and is being moved into a
directory that is shared or is the descendent of a directory that is
shared.

=cut
use constant kFPInsideSharedErr     => -5043;   # AFP 2.1
=item kFPInsideTrashErr

Shared directory is being moved into the Trash; a directory is being
moved to the trash and it contains a shared folder.

=cut
use constant kFPInsideTrashErr      => -5044;   # AFP 2.1
=item kFPPwdNeedsChangeErr

User's password needs to be changed.

=cut
use constant kFPPwdNeedsChangeErr   => -5045;   # AFP 2.2
=item kFPPwdPolicyErr

New password does not conform to the server's password policy.

=cut
use constant kFPPwdPolicyErr        => -5046;   # AFP 3.0
=item kFPDiskQuotaExceeded

Disk quota exceeded.

=cut
use constant kFPDiskQuotaExceeded   => -5047;   # AFP 3.1

our %errorcodes = (
    0       => 'No error occurred',
    -1066   => 'Incorrect ASP version number',
    -1067   => 'ASP transport buffer was too small',
    -1068   => 'No more sessions can be started',
    -1069   => 'No ASP server available',
    -1070   => 'Incorrect parameter specified',
    -1071   => 'Server too busy',
    -1072   => 'ASP session closed',
    -1073   => 'Incorrect size parameter given',
    -1074   => 'Too many client sessions',
    -1075   => 'Server did not acknowledge request',
    -5000   => 'Insufficient privileges',
    -5001   => 'Authentication is not yet complete',
    -5002   => 'Specified UAM is unknown',
    -5003   => 'Specified AFP version not supported',
    -5004   => 'Invalid bit in request bitmap',
    -5005   => 'Unable to move requested file',
    -5006   => 'Deny modes prevent requested operation',
    -5007   => 'Directory is not empty',
    -5008   => 'Volume was full during write',
    -5009   => 'End of file reached',
    -5010   => 'File is busy or exists during create',
    -5011   => 'Flat volume does not support directories',
    -5012   => 'Item was not found',
    -5013   => 'Range lock prevents operation',
    -5014   => 'Non-AFP error occurred',
    -5015   => 'Too many locks',
    -5016   => 'Server is not responding',
    -5017   => 'File already exists',
    -5018   => 'File does not exist',
    -5019   => 'Parameter out of range',
    -5020   => 'No lock on specified range exists',
    -5021   => 'Requested range overlaps an existing lock',
    -5022   => 'Session is closed',
    -5023   => 'Authentication failed',
    -5024   => 'Server did not recognize request',
    -5025   => 'Incorrect object type specified',
    -5026   => 'Too many open files',
    -5027   => 'Server is shutting down',
    -5028   => 'Cannot rename directory',
    -5029   => 'Directory does not exist',
    -5030   => 'Icon size is incorrect',
    -5031   => 'Volume is read only',
    -5032   => 'Inhibit attribute prevented operation',
    -5033   => 'Directory contains a share',
    -5034   => 'File ID not found',
    -5035   => 'File ID exists',
    -5036   => 'Incorrect volume specified',
    -5037   => 'Catalog has changed',
    -5038   => 'Source and target object are the same',
    -5039   => 'File ID is invalid',
    -5040   => 'Same password during change request',
    -5041   => 'Password was too short',
    -5042   => 'Password has expired',
    -5043   => 'Attempted to move directory containing share',
    -5044   => 'Attempted to move share into trash',
    -5045   => 'User must change password',
    -5046   => 'Password policy prevents new password',
    -5047   => 'Disk quota exceeded',
);

=back

=head1 FUNCTIONS

=over

=item afp_strerror (ERRNO)

Return a string containing the description of the error code ERRNO.

=cut
sub afp_strerror {
    my ($rc) = @_;
    return $errorcodes{$rc};
}

=back

=head1 AUTHOR

Derrik Pates <demon@now.ai>

=head1 SEE ALSO

C<Net::AFP>

=cut

1;
# vim: ts=4
