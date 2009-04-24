package Net::Atalk::ATP;

use constant ATP_TReq			=> (0x1 << 6);
use constant ATP_TResp			=> (0x2 << 6);
use constant ATP_TRel			=> (0x3 << 6);

use constant ATP_CTL_FNCODE		=> 0xC0;
use constant ATP_CTL_XOBIT		=> 0x20;
use constant ATP_CTL_EOMBIT		=> 0x10;
use constant ATP_CTL_STSBIT		=> 0x08;
use constant ATP_CTL_TREL_TMOUT	=> 0x07;

use constant ATP_TREL_30SEC		=> 0x00;
use constant ATP_TREL_1MIN		=> 0x01;
use constant ATP_TREL_2MIN		=> 0x02;
use constant ATP_TREL_4MIN		=> 0x03;
use constant ATP_TREL_8MIN		=> 0x04;

use constant ATP_MAXLEN			=> 578;

my $atp_header = 'CCnN';
my @atp_header_fields = ('ctl', 'bmp_seq', 'tid', 'msglen');

