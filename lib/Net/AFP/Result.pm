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
    $kFPNoErr               => q{No error occurred},
    -1066                   => q{Incorrect ASP version number},
    -1067                   => q{ASP transport buffer was too small},
    -1068                   => q{No more sessions can be started},
    -1069                   => q{No ASP server available},
    -1070                   => q{Incorrect parameter specified},
    -1071                   => q{Server too busy},
    -1072                   => q{ASP session closed},
    -1073                   => q{Incorrect size parameter given},
    -1074                   => q{Too many client sessions},
    -1075                   => q{Server did not acknowledge request},
    $kFPAccessDenied        => q{Insufficient privileges},
    $kFPAuthContinue        => q{Authentication is not yet complete},
    $kFPBadUAM              => q{Specified UAM is unknown},
    $kFPBadVersNum          => q{Specified AFP version not supported},
    $kFPBitmapErr           => q{Invalid bit in request bitmap},
    $kFPCantMove            => q{Unable to move requested file},
    $kFPDenyConflict        => q{Deny modes prevent requested operation},
    $kFPDirNotEmpty         => q{Directory is not empty},
    $kFPDiskFull            => q{Volume was full during write},
    $kFPEOFErr              => q{End of file reached},
    $kFPFileBusy            => q{File is busy or exists during create},
    $kFPFlatVol             => q{Flat volume does not support directories},
    $kFPItemNotFound        => q{Item was not found},
    $kFPLockErr             => q{Range lock prevents operation},
    $kFPMiscErr             => q{Non-AFP error occurred},
    $kFPNoMoreLocks         => q{Too many locks},
    $kFPNoServer            => q{Server is not responding},
    $kFPObjectExists        => q{File already exists},
    $kFPObjectNotFound      => q{File does not exist},
    $kFPParamErr            => q{Parameter out of range},
    $kFPRangeNotLocked      => q{No lock on specified range exists},
    $kFPRangeOverlap        => q{Requested range overlaps an existing lock},
    $kFPSessClosed          => q{Session is closed},
    $kFPUserNotAuth         => q{Authentication failed},
    $kFPCallNotSupported    => q{Server did not recognize request},
    $kFPObjectTypeErr       => q{Incorrect object type specified},
    $kFPTooManyFilesOpen    => q{Too many open files},
    $kFPServerGoingDown     => q{Server is shutting down},
    $kFPCantRename          => q{Cannot rename directory},
    $kFPDirNotFound         => q{Directory does not exist},
    $kFPIconTypeError       => q{Icon size is incorrect},
    $kFPVolLocked           => q{Volume is read only},
    $kFPObjectLocked        => q{Inhibit attribute prevented operation},
    $kFPContainsSharedErr   => q{Directory contains a share},
    $kFPIDNotFound          => q{File ID not found},
    $kFPIDExists            => q{File ID exists},
    $kFPDiffVolErr          => q{Incorrect volume specified},
    $kFPCatalogChanged      => q{Catalog has changed},
    $kFPSameObjectErr       => q{Source and target object are the same},
    $kFPBadIDErr            => q{File ID is invalid},
    $kFPPwdSameErr          => q{Same password during change request},
    $kFPPwdTooShortErr      => q{Password was too short},
    $kFPPwdExpiredErr       => q{Password has expired},
    $kFPInsideSharedErr     => q{Attempted to move directory containing share},
    $kFPInsideTrashErr      => q{Attempted to move share into trash},
    $kFPPwdNeedsChangeErr   => q{User must change password},
    $kFPPwdPolicyErr        => q{Password policy prevents new password},
    $kFPDiskQuotaExceeded   => q{Disk quota exceeded},
);

sub afp_strerror {
    my ($rc) = @_;
    return $errorcodes{$rc};
}

1;
# vim: ts=4
