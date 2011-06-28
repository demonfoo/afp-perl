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

=cut
use constant kFPNoErr               => 0;
=item kASPBadVersNum

=cut
use constant kASPBadVersNum         => -1066;
=item kASPBufTooSmall

=cut
use constant kASPBufTooSmall        => -1067;
=item kFPNoMoreSessions

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

=cut
use constant kFPAccessDenied        => -5000;
=item kFPAuthContinue

=cut
use constant kFPAuthContinue        => -5001;
=item kFPBadUAM

=cut
use constant kFPBadUAM              => -5002;
=item kFPBadVersNum

=cut
use constant kFPBadVersNum          => -5003;
=item kFPBitmapErr

=cut
use constant kFPBitmapErr           => -5004;
=item kFPCantMove

=cut
use constant kFPCantMove            => -5005;
=item kFPDenyConflict

=cut
use constant kFPDenyConflict        => -5006;
=item kFPDirNotEmpty

=cut
use constant kFPDirNotEmpty         => -5007;
=item kFPDiskFull

=cut
use constant kFPDiskFull            => -5008;
=item kFPEOFErr

=cut
use constant kFPEOFErr              => -5009;
=item kFPFileBusy

=cut
use constant kFPFileBusy            => -5010;
=item kFPFlatVol

=cut
use constant kFPFlatVol             => -5011;
=item kFPItemNotFound

=cut
use constant kFPItemNotFound        => -5012;
=item kFPLockErr

=cut
use constant kFPLockErr             => -5013;
=item kFPMiscErr

=cut
use constant kFPMiscErr             => -5014;
=item kFPNoMoreLocks

=cut
use constant kFPNoMoreLocks         => -5015;
=item kFPNoServer

=cut
use constant kFPNoServer            => -5016;
=item kFPObjectExists

=cut
use constant kFPObjectExists        => -5017;
=item kFPObjectNotFound

=cut
use constant kFPObjectNotFound      => -5018;
=item kFPParamErr

=cut
use constant kFPParamErr            => -5019;
=item kFPRangeNotLocked

=cut
use constant kFPRangeNotLocked      => -5020;
=item kFPRangeOverlap

=cut
use constant kFPRangeOverlap        => -5021;
=item kFPSessClosed

=cut
use constant kFPSessClosed          => -5022;
=item kFPUserNotAuth

=cut
use constant kFPUserNotAuth         => -5023;
=item kFPCallNotSupported

=cut
use constant kFPCallNotSupported    => -5024;
=item kFPObjectTypeErr

=cut
use constant kFPObjectTypeErr       => -5025;
=item kFPTooManyFilesOpen

=cut
use constant kFPTooManyFilesOpen    => -5026;
=item kFPServerGoingDown

=cut
use constant kFPServerGoingDown     => -5027;
=item kFPCantRename

=cut
use constant kFPCantRename          => -5028;
=item kFPDirNotFound

=cut
use constant kFPDirNotFound         => -5029;
=item kFPIconTypeError

=cut
use constant kFPIconTypeError       => -5030;
=item kFPVolLocked

=cut
use constant kFPVolLocked           => -5031;
=item kFPObjectLocked

=cut
use constant kFPObjectLocked        => -5032;
=item kFPContainsSharedErr

=cut
use constant kFPContainsSharedErr   => -5033;
=item kFPIDNotFound

=cut
use constant kFPIDNotFound          => -5034;   # AFP 2.1
=item kFPIDExists

=cut
use constant kFPIDExists            => -5035;   # AFP 2.1
=item kFPDiffVolErr

=cut
use constant kFPDiffVolErr          => -5036;   # AFP 2.1
=item kFPCatalogChanged

=cut
use constant kFPCatalogChanged      => -5037;   # AFP 2.1
=item kFPSameObjectErr

=cut
use constant kFPSameObjectErr       => -5038;   # AFP 2.1
=item kFPBadIDErr

=cut
use constant kFPBadIDErr            => -5039;   # AFP 2.1
=item kFPPwdSameErr

=cut
use constant kFPPwdSameErr          => -5040;   # AFP 2.1
=item kFPPwdTooShortErr

=cut
use constant kFPPwdTooShortErr      => -5041;   # AFP 2.1
=item kFPPwdExpiredErr

=cut
use constant kFPPwdExpiredErr       => -5042;   # AFP 2.1
=item kFPInsideSharedErr

=cut
use constant kFPInsideSharedErr     => -5043;   # AFP 2.1
=item kFPInsideTrashErr

=cut
use constant kFPInsideTrashErr      => -5044;   # AFP 2.1
=item kFPPwdNeedsChangeErr

=cut
use constant kFPPwdNeedsChangeErr   => -5045;   # AFP 2.2
=item kFPPwdPolicyErr

=cut
use constant kFPPwdPolicyErr        => -5046;   # AFP 3.0
=item kFPDiskQuotaExceeded

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
