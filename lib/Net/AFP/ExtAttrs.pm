package Net::AFP::ExtAttrs;

use strict;
use warnings;
use Exporter qw(import);
use Readonly;

our @EXPORT = qw($kXAttrNoFollow $kXAttrCreate $kXAttrReplace);

Readonly our $kXAttrNoFollow    => 0x1;
Readonly our $kXAttrCreate      => 0x2;
Readonly our $kXAttrReplace     => 0x4;

1;
