# IO::Socket::DDP.pm

package IO::Socket::DDP;

use strict;
our(@ISA, $VERSION);
use IO::Socket;
use Net::Atalk;
use Carp;
use Errno qw(EINVAL ETIMEDOUT);

@ISA = qw(IO::Socket);
$VERSION = "0.50";

=head1 NAME

IO::Socket::DDP - Object interface for AF_APPLETALK domain sockets

=head1 SYNOPSIS

    use IO::Socket::DDP;

=head1 DESCRIPTION

C<IO::Socket::DDP> provices an object-based interface to creating and using
sockets in the AF_APPLETALK domain. It is built upon the L<IO::Socket>
interface and inherits all the methods defined by L<IO::Socket>.

=head1 CONSTRUCTOR

=over

=item new ( [ARGS] )

Creates an C<IO::Socket::DDP> object, which is a reference to a newly
created symbol (see the C<Symbol> package). C<new> optionally takes
arguments; these arguments are presented as key/value pairs.

    PeerAddr    Remote host address
    PeerHost    Synonym for PeerAddr
    PeerPort    Remote port or service
    LocalAddr   Local host bind address
    LocalHost   Synonym for LocalAddr
    LocalPort   Local host bind port
    Proto       Protocol name (or number)
    Type        Socket type
    Listen      Queue size for listen
    ReuseAddr   Set SO_REUSEADDR before binding
    Reuse       Set SO_REUSEADDR before binding (deprecated, prefer ReuseAddr)
    ReusePort   Set SO_REUSEPORT before binding
    Broadcast   Set SO_BROADCAST before binding
    Timeout     Timeout value for some operations
    MultiHomed  Try all addresses for multi-homed hosts
    Blocking    Determine if connection will be blocking mode

if C<Listen> is defined then a listen socket is created, otherwise if
the socket type, which is derived from the protocol, is SOCK_STREAM then
connect() is called.

Although it is not illegal, the use of C<MultiHomed> on a socket
which is in non-blocking mode is of little use. This is because the
first connect will never fail with a timeout as the connect call
will not block.

The C<PeerAddr> can be an Appletalk host address in the "xxxxx.xxx"
format. Support will eventually be added for resolving NBP station names,
but is not currently available.

If C<Proto> is not given and you specify a symbolic C<PeerPort> port,
then the constructor will try to derive  C<Proto> from the service name.
As a loast reort, C<Proto> "ddp" is assumed. The C<Type> parameter
will be deduced from C<Proto> if not specified.

If the constructor is only passed a single argument, it is assumed to
be a C<PeerAddr> specification.

If C<Blocking> is set to 0, the socket will be in nonblocking mode. If
not specified it defaults to 1 (blocking mode).

 NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE

As of VERSION 1.18 all IO::Socket objects have autoflush turned on
by default. This was not the case with earlier releases.

 NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE

=back

=head2 METHODS

=over

=item sockaddr ()

Returns the address part of the sockaddr structure for the socket.

=item sockport ()

Returns the port number that the socket is using on the local host.

=item sockhost ()

Returns the address part of the sockaddr structure for the socket in a
text form xxxxx.xxx.

=item peeraddr ()

Return the address part of the sockaddr structure for the socket on
the peer host.

=item peerport ()

Return the port number for the socket on the peer host.

=item peerhost ()

Return the address part of the sockaddr structure for the socket on the
peer host in a text form xxxxx.xxx.

=back

=head1 SEE ALSO

L<Net::Atalk>, L<IO::Socket>

=head1 AUTHOR

Derrik Pates <demon@devrandom.net>, based on code written by Graham
Barr and maintained by the Perl Porters.

=cut

IO::Socket::DDP->register_domain( AF_APPLETALK );

my %socket_type = ( 'ddp' => SOCK_DGRAM );
my %proto_number;
$proto_number{'ddp'}  = 37;
my %proto_name = reverse %proto_number;

sub new {
    my $class = shift;
    unshift(@_, "PeerAddr") if @_ == 1;
    return $class->SUPER::new(@_);
}

sub _cache_proto {
    my @proto = @_;
    for (map lc($_), $proto[0], split(' ', $proto[1])) {
	$proto_number{$_} = $proto[2];
    }
    $proto_name{$proto[2]} = $proto[0];
}

sub _get_proto_number {
    my $name = lc(shift);
    return undef unless defined $name;
    return $proto_number{$name} if exists $proto_number{$name};

    my @proto = getprotobyname($name);
    return undef unless @proto;
    _cache_proto(@proto);

    return $proto[2];
}

sub _get_proto_name {
    my $num = shift;
    return undef unless defined $num;
    return $proto_name{$num} if exists $proto_name{$num};

    my @proto = getprotobynumber($num);
    return undef unless @proto;
    _cache_proto(@proto);

    return $proto[0];
}

sub _sock_info {
  my($addr,$port,$proto) = @_;
  my $origport = $port;
  my @serv = ();

  $port = $1
	if(defined $addr && $addr =~ s,:([\w\(\)/]+)$,,);

  if(defined $proto  && $proto =~ /\D/) {
    my $num = _get_proto_number($proto);
    unless (defined $num) {
      $@ = "Bad protocol '$proto'";
      return;
    }
    $proto = $num;
  }

  if(defined $port) {
    my $defport = ($port =~ s,\((\d+)\)$,,) ? $1 : undef;
    my $pnum = ($port =~ m,^(\d+)$,)[0];

    @serv = getservbyname($port, _get_proto_name($proto) || "")
	if ($port =~ m,\D,);

    $port = $serv[2] || $defport || $pnum;
    unless (defined $port) {
	$@ = "Bad service '$origport'";
	return;
    }

    $proto = _get_proto_number($serv[3]) if @serv && !$proto;
  }

 return ($addr || undef,
	 $port || undef,
	 $proto || undef
	);
}

sub _error {
    my $sock = shift;
    my $err = shift;
    {
      local($!);
      my $title = ref($sock).": ";
      $@ = join("", $_[0] =~ /^$title/ ? "" : $title, @_);
      $sock->close()
	if(defined fileno($sock));
    }
    $! = $err;
    return undef;
}

sub _get_addr {
    my($sock,$addr_str, $multi) = @_;
    my @addr;
    atalk_aton($addr_str);
}

sub configure {
    my($sock,$arg) = @_;
    my($lport,$rport,$laddr,$raddr,$proto,$type);

    $arg->{LocalAddr} = $arg->{LocalHost}
	if exists $arg->{LocalHost} && !exists $arg->{LocalAddr};

    ($laddr,$lport,$proto) = _sock_info($arg->{LocalAddr},
					$arg->{LocalPort},
					$arg->{Proto})
			or return _error($sock, $!, $@);

    $laddr = defined $laddr ? atalk_aton($laddr)
			    : ATADDR_ANY;

    return _error($sock, EINVAL, "Bad hostname '",$arg->{LocalAddr},"'")
	unless(defined $laddr);

    $arg->{PeerAddr} = $arg->{PeerHost}
	if exists $arg->{PeerHost} && !exists $arg->{PeerAddr};

    unless(exists $arg->{Listen}) {
	($raddr,$rport,$proto) = _sock_info($arg->{PeerAddr},
					    $arg->{PeerPort},
					    $proto)
			or return _error($sock, $!, $@);
    }

    $proto ||= _get_proto_number('ddp');

    $type = $arg->{Type} || $socket_type{lc _get_proto_name($proto)};

    my @raddr = ();

    if(defined $raddr) {
	@raddr = $sock->_get_addr($raddr, $arg->{MultiHomed});
	return _error($sock, EINVAL, "Bad hostname '",$arg->{PeerAddr},"'")
	    unless @raddr;
    }

    while(1) {

	$sock->socket(AF_APPLETALK, $type, 0) or
	    return _error($sock, $!, "$!");

        if (defined $arg->{Blocking}) {
	    defined $sock->blocking($arg->{Blocking})
		or return _error($sock, $!, "$!");
	}

	if ($arg->{Reuse} || $arg->{ReuseAddr}) {
	    $sock->sockopt(SO_REUSEADDR,1) or
		    return _error($sock, $!, "$!");
	}

	if ($arg->{ReusePort}) {
	    $sock->sockopt(SO_REUSEPORT,1) or
		    return _error($sock, $!, "$!");
	}

	if ($arg->{Broadcast}) {
		$sock->sockopt(SO_BROADCAST,1) or
		    return _error($sock, $!, "$!");
	}

	if($lport || exists $arg->{Listen} || $^O ne 'linux') {
	    $sock->bind($lport || 0, $laddr) or
		    return _error($sock, $!, "$!");
	}

	if(exists $arg->{Listen}) {
	    $sock->listen($arg->{Listen} || 5) or
		return _error($sock, $!, "$!");
	    last;
	}

 	# don't try to connect unless we're given a PeerAddr
 	last unless exists($arg->{PeerAddr});
 
        $raddr = shift @raddr;

	return _error($sock, EINVAL, 'Cannot determine remote port')
		unless($rport || $type == SOCK_DGRAM || $type == SOCK_RAW);

	last
	    unless($type == SOCK_STREAM || defined $raddr);

	return _error($sock, EINVAL, "Bad hostname '",$arg->{PeerAddr},"'")
	    unless defined $raddr;

#        my $timeout = ${*$sock}{'io_socket_timeout'};
#        my $before = time() if $timeout;

	undef $@;
        if ($sock->connect(pack_sockaddr_at($rport, $raddr))) {
#            ${*$sock}{'io_socket_timeout'} = $timeout;
            return $sock;
        }

	return _error($sock, $!, $@ || 'Timeout')
	    unless @raddr;

#	if ($timeout) {
#	    my $new_timeout = $timeout - (time() - $before);
#	    return _error($sock, ETIMEDOUT, 'Timeout') if $new_timeout <= 0;
#	    ${*$sock}{'io_socket_timeout'} = $new_timeout;
#        }

    }

    $sock;
}

sub connect {
    @_ == 2 || @_ == 3 or
       croak 'usage: $sock->connect(NAME) or $sock->connect(PORT, ADDR)';
    my $sock = shift;
    return $sock->SUPER::connect(@_ == 1 ? shift : pack_sockaddr_at(@_));
}

sub bind {
    @_ == 2 || @_ == 3 or
       croak 'usage: $sock->bind(NAME) or $sock->bind(PORT, ADDR)';
    my $sock = shift;
    return $sock->SUPER::bind(@_ == 1 ? shift : pack_sockaddr_at(@_))
}

sub sockaddr {
    @_ == 1 or croak 'usage: $sock->sockaddr()';
    my($sock) = @_;
    my $name = $sock->sockname;
    $name ? (unpack_sockaddr_at($name))[1] : undef;
}

sub sockport {
    @_ == 1 or croak 'usage: $sock->sockport()';
    my($sock) = @_;
    my $name = $sock->sockname;
    $name ? (unpack_sockaddr_at($name))[0] : undef;
}

sub sockhost {
    @_ == 1 or croak 'usage: $sock->sockhost()';
    my($sock) = @_;
    my $addr = $sock->sockaddr;
    $addr ? atalk_ntoa($addr) : undef;
}

sub peeraddr {
    @_ == 1 or croak 'usage: $sock->peeraddr()';
    my($sock) = @_;
    my $name = $sock->peername;
    $name ? (unpack_sockaddr_at($name))[1] : undef;
}

sub peerport {
    @_ == 1 or croak 'usage: $sock->peerport()';
    my($sock) = @_;
    my $name = $sock->peername;
    $name ? (unpack_sockaddr_at($name))[0] : undef;
}

sub peerhost {
    @_ == 1 or croak 'usage: $sock->peerhost()';
    my($sock) = @_;
    my $addr = $sock->peeraddr;
    $addr ? atalk_ntoa($addr) : undef;
}

1;

__END__

