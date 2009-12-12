package Net::AFP::ExtAttrs;

use Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(kXAttrNoFollow kXAttrCreate kXAttrReplace);

use constant kXAttrNoFollow	=> 0x1;
use constant kXAttrCreate	=> 0x2;
use constant kXAttrReplace	=> 0x4;

1;
