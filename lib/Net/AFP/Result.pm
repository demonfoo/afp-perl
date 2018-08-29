package Net::AFP::Result;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kFPNoErr $kFPAccessDenied $kFPAuthContinue $kFPBadUAM
                 $kFPBadVersNum $kFPBitmapErr $kFPCantMove $kFPDenyConflict
                 $kFPDirNotEmpty $kFPDiskFull $kFPEOFErr $kFPFileBusy
                 $kFPFlatVol $kFPItemNotFound $kFPLockErr $kFPMiscErr
                 $kFPNoMoreLocks $kFPNoServer $kFPObjectExists
                 $kFPObjectNotFound $kFPParamErr $kFPRangeNotLocked
                 $kFPRangeOverlap $kFPSessClosed $kFPUserNotAuth
                 $kFPCallNotSupported $kFPObjectTypeErr $kFPTooManyFilesOpen
                 $kFPServerGoingDown $kFPCantRename $kFPDirNotFound
                 $kFPIconTypeErr $kFPVolLocked $kFPObjectLocked
                 $kFPContainsSharedErr $kFPIDNotFound $kPIDExists
                 $kFPCatalogChanged $kFPSameObjectErr $kFPBadIDErr
                 $kFPPwdSameErr $kFPPwdTooShortErr $kFPPwdExpiredErr
                 $kFPInsideSharedErr $kFPInsideTrashErr $kFPPwdNeedsChangeErr
                 $kFPPwdPolicyErr $kFPDiskQuotaExceeded afp_strerror);

Readonly our $kFPNoErr              => 0;
Readonly our $kFPAccessDenied       => -5000;
Readonly our $kFPAuthContinue       => -5001;
Readonly our $kFPBadUAM             => -5002;
Readonly our $kFPBadVersNum         => -5003;
Readonly our $kFPBitmapErr          => -5004;
Readonly our $kFPCantMove           => -5005;
Readonly our $kFPDenyConflict       => -5006;
Readonly our $kFPDirNotEmpty        => -5007;
Readonly our $kFPDiskFull           => -5008;
Readonly our $kFPEOFErr             => -5009;
Readonly our $kFPFileBusy           => -5010;
Readonly our $kFPFlatVol            => -5011;
Readonly our $kFPItemNotFound       => -5012;
Readonly our $kFPLockErr            => -5013;
Readonly our $kFPMiscErr            => -5014;
Readonly our $kFPNoMoreLocks        => -5015;
Readonly our $kFPNoServer           => -5016;
Readonly our $kFPObjectExists       => -5017;
Readonly our $kFPObjectNotFound     => -5018;
Readonly our $kFPParamErr           => -5019;
Readonly our $kFPRangeNotLocked     => -5020;
Readonly our $kFPRangeOverlap       => -5021;
Readonly our $kFPSessClosed         => -5022;
Readonly our $kFPUserNotAuth        => -5023;
Readonly our $kFPCallNotSupported   => -5024;
Readonly our $kFPObjectTypeErr      => -5025;
Readonly our $kFPTooManyFilesOpen   => -5026;
Readonly our $kFPServerGoingDown    => -5027;
Readonly our $kFPCantRename         => -5028;
Readonly our $kFPDirNotFound        => -5029;
Readonly our $kFPIconTypeError      => -5030;
Readonly our $kFPVolLocked          => -5031;
Readonly our $kFPObjectLocked       => -5032;
Readonly our $kFPContainsSharedErr  => -5033;
Readonly our $kFPIDNotFound         => -5034;   # AFP 2.1
Readonly our $kFPIDExists           => -5035;   # AFP 2.1
Readonly our $kFPDiffVolErr         => -5036;   # AFP 2.1
Readonly our $kFPCatalogChanged     => -5037;   # AFP 2.1
Readonly our $kFPSameObjectErr      => -5038;   # AFP 2.1
Readonly our $kFPBadIDErr           => -5039;   # AFP 2.1
Readonly our $kFPPwdSameErr         => -5040;   # AFP 2.1
Readonly our $kFPPwdTooShortErr     => -5041;   # AFP 2.1
Readonly our $kFPPwdExpiredErr      => -5042;   # AFP 2.1
Readonly our $kFPInsideSharedErr    => -5043;   # AFP 2.1
Readonly our $kFPInsideTrashErr     => -5044;   # AFP 2.1
Readonly our $kFPPwdNeedsChangeErr  => -5045;   # AFP 2.2
Readonly our $kFPPwdPolicyErr       => -5046;   # AFP 3.0
Readonly our $kFPDiskQuotaExceeded  => -5047;   # AFP 3.1

my %errorcodes = (
    $kFPNoErr               => 'No error occurred',
    -1066                   => 'Incorrect ASP version number',
    -1067                   => 'ASP transport buffer was too small',
    -1068                   => 'No more sessions can be started',
    -1069                   => 'No ASP server available',
    -1070                   => 'Incorrect parameter specified',
    -1071                   => 'Server too busy',
    -1072                   => 'ASP session closed',
    -1073                   => 'Incorrect size parameter given',
    -1074                   => 'Too many client sessions',
    -1075                   => 'Server did not acknowledge request',
    $kFPAccessDenied        => 'Insufficient privileges',
    $kFPAuthContinue        => 'Authentication is not yet complete',
    $kFPBadUAM              => 'Specified UAM is unknown',
    $kFPBadVersNum          => 'Specified AFP version not supported',
    $kFPBitmapErr           => 'Invalid bit in request bitmap',
    $kFPCantMove            => 'Unable to move requested file',
    $kFPDenyConflict        => 'Deny modes prevent requested operation',
    $kFPDirNotEmpty         => 'Directory is not empty',
    $kFPDiskFull            => 'Volume was full during write',
    $kFPEOFErr              => 'End of file reached',
    $kFPFileBusy            => 'File is busy or exists during create',
    $kFPFlatVol             => 'Flat volume does not support directories',
    $kFPItemNotFound        => 'Item was not found',
    $kFPLockErr             => 'Range lock prevents operation',
    $kFPMiscErr             => 'Non-AFP error occurred',
    $kFPNoMoreLocks         => 'Too many locks',
    $kFPNoServer            => 'Server is not responding',
    $kFPObjectExists        => 'File already exists',
    $kFPObjectNotFound      => 'File does not exist',
    $kFPParamErr            => 'Parameter out of range',
    $kFPRangeNotLocked      => 'No lock on specified range exists',
    $kFPRangeOverlap        => 'Requested range overlaps an existing lock',
    $kFPSessClosed          => 'Session is closed',
    $kFPUserNotAuth         => 'Authentication failed',
    $kFPCallNotSupported    => 'Server did not recognize request',
    $kFPObjectTypeErr       => 'Incorrect object type specified',
    $kFPTooManyFilesOpen    => 'Too many open files',
    $kFPServerGoingDown     => 'Server is shutting down',
    $kFPCantRename          => 'Cannot rename directory',
    $kFPDirNotFound         => 'Directory does not exist',
    $kFPIconTypeError       => 'Icon size is incorrect',
    $kFPVolLocked           => 'Volume is read only',
    $kFPObjectLocked        => 'Inhibit attribute prevented operation',
    $kFPContainsSharedErr   => 'Directory contains a share',
    $kFPIDNotFound          => 'File ID not found',
    $kFPIDExists            => 'File ID exists',
    $kFPDiffVolErr          => 'Incorrect volume specified',
    $kFPCatalogChanged      => 'Catalog has changed',
    $kFPSameObjectErr       => 'Source and target object are the same',
    $kFPBadIDErr            => 'File ID is invalid',
    $kFPPwdSameErr          => 'Same password during change request',
    $kFPPwdTooShortErr      => 'Password was too short',
    $kFPPwdExpiredErr       => 'Password has expired',
    $kFPInsideSharedErr     => 'Attempted to move directory containing share',
    $kFPInsideTrashErr      => 'Attempted to move share into trash',
    $kFPPwdNeedsChangeErr   => 'User must change password',
    $kFPPwdPolicyErr        => 'Password policy prevents new password',
    $kFPDiskQuotaExceeded   => 'Disk quota exceeded',
);

sub afp_strerror {
    my ($rc) = @_;
    return $errorcodes{$rc};
}

1;
# vim: ts=4
