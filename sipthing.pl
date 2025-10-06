#!/usr/bin/perl

# have crude sip conversation
# jkister 2023060901

use strict;
use IO::Socket;
use Digest::MD5 qw(md5_hex);
use Getopt::Long qw(:config no_ignore_case); # -D debug vs date

my %opt;
GetOptions( \%opt, 'debug|D',
                   'host=s',
                   'port=i',
                   'proto=s',
                   'localport=i',
                   'ruri=s',
                   'from=s',
                   'fromname=s',
                   'to=s',
                   'useragent=s',
                   'mode=s',
                   'callid=s',
                   'branch=s',
                   'fromtag=s',
                   'fromhost=s',
                   'tohost=s',
                   'allow=s',
                   'quiet',
                   'pai',
                   'padding=i',
                   'identity=s',
                   'indicator=s',
                   'cseq=i',
                   'sipfile=s', # NB some devices wont respond if date too old
                   'limit=i',
                   'extra=s@',
                   'date=s', # .. some wont respond if date too old
                   'contact_user=s',
                   'contact_host=s',
                   'username=s',
                   'password=s',
          );

# date can be like: date --date="2 min ago" +'%a, %d %b %Y %H:%M:%S %Z'
                
$opt{host}      || die "specify --host <host>\n";
$opt{port}      ||= 5060;
$opt{proto}     ||= 'udp';
$opt{localport} ||= int(rand(55534)) + 10001;
$opt{from}      ||= 'sipthing';
$opt{fromname}  ||= $opt{from};
$opt{to}        ||= $opt{from};
$opt{contact_user} ||= $opt{from};
$opt{useragent} ||= 'sipthing/0.56';
$opt{mode}      ||= 'options';
$opt{callid}    ||= join '', map { unpack 'H*', chr(rand(256)) } 1..16;
$opt{branch}    ||= join '', map { unpack 'H*', chr(rand(256)) } 1..16;
$opt{fromtag}   ||= join '', map { unpack 'H*', chr(rand(256)) } 1..4;
$opt{allow}     ||= 'ACK, BYE';
$opt{cseq}      ||= int(rand(32)) + 1;
$opt{limit}       = 70 unless defined $opt{limit}; # could be 0

if( $opt{indicator} ){
    $opt{indicator} = uc($opt{indicator});
    die "bad indicator\n" unless $opt{indicator} =~ /^[ABC]$/;
}

$opt{proto} = uc($opt{proto});

$opt{mode} eq 'invite' || $opt{mode} eq 'options' || die "invalid --mode\n";

$|=1;
my $sock = IO::Socket::INET->new(PeerAddr  => $opt{host},
                                 PeerPort  => $opt{port},
                                 LocalPort => $opt{localport},
                                 ReuseAddr => 1,
                                 Proto     => $opt{proto},
                                ) or die "socket error: $!\n";

$sock->setsockopt(SOL_SOCKET, SO_RCVTIMEO, pack('l!l!', 5, 0)) or die "setsockopt: $!\n";

my $myport       = $sock->sockport();
my $myhost       = $sock->sockhost();
my $peerport     = $sock->peerport();
my $peerhost     = $sock->peerhost();
$opt{fromhost}     ||= $myhost;
$opt{contact_host} ||= $opt{fromhost};
$opt{tohost}       ||= $peerhost;
$opt{ruri}         ||= 'sip:' . $opt{to} . '@' . $opt{tohost};

my @dmap = qw/Sun Mon Tue Wed Thu Fri Sat/;
my @mmap = qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
my ($sec,$min,$hour,$mday,$mon,$year,$wday) = (gmtime())[0,1,2,3,4,5,6];

my $date = $opt{date} ? $opt{date} : sprintf('%s, %02d %s %04d %02d:%02d:%02d',
                                      $dmap[$wday], $mday, $mmap[$mon],
                                      ($year+1900),$hour,$min,$sec) . ' GMT';

my $options = <<__EOO__;
OPTIONS $opt{ruri} SIP/2.0
Via: SIP/2.0/$opt{proto} $opt{fromhost}:${myport};branch=$opt{branch}
Contact: <sip:$opt{contact_user}\@$opt{contact_host}:$myport>
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}:$myport>;tag=$opt{fromtag}
To: <sip:$opt{to}\@$opt{tohost}:$peerport>
Call-ID: $opt{callid}\@$opt{fromhost}:$myport
CSeq: $opt{cseq} OPTIONS
User-Agent: $opt{useragent}
Date: $date
Allow: $opt{allow}
Content-Length: 0
__EOO__

if( $opt{padding} ){
    $options .= "\n" . "X-Padding: " . 'A' x $opt{padding};
}
$options .= "\n";


my $sdp = <<__EOSDP__;
v=0
o=root 6959 6959 IN IP4 $opt{fromhost}
s=session
c=IN IP4 $opt{fromhost}
t=0 0
m=audio 29856 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=silenceSupp:off - - - -
a=ptime:20
a=sendrecv
__EOSDP__

my $length = length($sdp) + 12 + 2; # +12 for each line\r and +2 for final empty line \r\n

my (@invite,@bare_invite);
if( $opt{sipfile} ){
    open(my $fh, $opt{sipfile}) || die "cannot open $opt{sipfile}: $!\n";
    chomp(@invite = <$fh>);
    close $fh;
    push @invite, "\n";
}else{
    @invite = split "\n", <<__EOI__;
INVITE $opt{ruri} SIP/2.0
Via: SIP/2.0/$opt{proto} $opt{fromhost}:$myport;branch=$opt{branch};rport=$myport
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}>;tag=$opt{fromtag}
To: <sip:$opt{to}\@$opt{tohost}:$opt{port}>
Contact: <sip:$opt{contact_user}\@$opt{contact_host}:$myport>
Call-ID: $opt{callid}\@$opt{fromhost}:$myport
CSeq: $opt{cseq} INVITE
User-Agent: $opt{useragent}
Max-Forwards: 69
Remote-Party-ID: "$opt{from}" <sip:$opt{from}\@$opt{fromhost}>;privacy=off;screen=no
Date: $date
Allow: $opt{allow}
Content-Type: application/sdp
Content-Length: $length
__EOI__

    if( $opt{indicator} ){
        push @invite, "P-Attestation-Indicator: $opt{indicator}";
    }
    if( $opt{identity} ){
        push @invite, "Identity: $opt{identity}";
    }
    if( $opt{pai} ){
        push @invite, "P-Asserted-Identity: <sip:$opt{from}\@$myhost:$myport>";
    }
    if( $opt{fromhost} ne $myhost ){
        push @invite, "Via: SIP/2.0/$opt{proto} $opt{fromhost}:${myport};branch=$opt{branch}";
    }
    if( $opt{padding} ){
        push @invite, "X-Padding: " . 'A' x $opt{padding};
    }
    for my $field (@{ $opt{extra} }){
        push @invite, $field;
    }
    
    @bare_invite = @invite;
    push @invite, ('', split("\n", $sdp), "\n");
}

my $cancel = <<__EOCANCEL__;
CANCEL $opt{ruri} SIP/2.0
Via: SIP/2.0/$opt{proto} $myhost:$myport;branch=$opt{branch}
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}>;tag=$opt{fromtag}
To: <sip:$opt{to}\@$opt{tohost}:$opt{port}>;tag=%%totag%%
Contact: <sip:$opt{from}\@$opt{fromhost}>
Call-ID: $opt{callid}\@$myhost:$myport
CSeq: $opt{cseq} CANCEL
User-Agent: $opt{useragent}
Content-Length: 0

__EOCANCEL__

my $ack = <<__EOACK__;
ACK $opt{ruri} SIP/2.0
Via: SIP/2.0/$opt{proto} $myhost:$myport;branch=$opt{branch}
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}>;tag=$opt{fromtag}
To: <sip:$opt{to}\@$opt{tohost}:$opt{port}>;tag=%%totag%%
Contact: <sip:$opt{contact_user}\@$opt{contact_host}:$myport>
Call-ID: $opt{callid}\@$myhost:$myport
CSeq: $opt{cseq} ACK
User-Agent: $opt{useragent}
Content-Length: 0

__EOACK__

my $ok = <<__EOOK__;
SIP/2.0 200 OK
Via: SIP/2.0/$opt{proto} $myhost:$myport;branch=$opt{branch}
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}>;tag=$opt{fromtag}
To: <sip:$opt{to}\@$opt{tohost}:$opt{port}>;tag=%%totag%%
Call-ID: $opt{callid}\@$myhost:$myport
CSeq: $opt{cseq} OK
User-Agent: $opt{useragent}
Content-Length: 0

__EOOK__


my %packet = ( invite  => join("\n", @invite),
               options => $options,
               ack     => $ack,
               cancel  => $cancel,
               ok      => $ok,
             );

for my $type (keys %packet){
    $packet{$type} =~ s/\x0D?\x0A/\x0D\x0A/g;
}

my $payload_size = length($packet{ $opt{mode} });
my $total_size = $payload_size + 20 + 8; # + ip header + udp header

debug( "**** TX [1] $myhost:$myport -> $peerhost:$peerport\n",
       "***** with $total_size byte packet ($payload_size byte payload):\n",
       "--- \n",
       $packet{ $opt{mode} },
       "--- ");

$sock->send($packet{ $opt{mode} }) or die "send error: $!\n";
$sock->timeout(1);


my $tx = 1;
my $loop = 1;
my $rx = 0;
while( $loop <= $opt{limit} ){
    $sock->recv(my $pkt, 65535);
    next unless $pkt;

    $rx++;
    my $sl = (split /\r?\n/, $pkt)[0];
    print "**** RX [$rx] $peerhost:$peerport -> $myhost:$myport\n";
    if( $opt{quiet} ){
        print "$sl\n";
    }else{
        print "--- \n",
              $pkt,
              "--- \n";
    }
    exit if $opt{mode} eq 'options';

    if( $pkt =~ /^To:.+;tag=(\S+)/im ){
        my $totag = $1;
        debug( "caught totag: ", $totag );
        for my $type (qw/cancel ack/){
            $packet{$type} =~ s/(^To: .*?);tag=[^;\r\n]+/$1;tag=$totag/im;
        }
    }

    if( $pkt =~ /^Contact: <([^>]+)>/im ){
        my $r_contact_uri = $1;
        debug( "caught remote contact uri: ", $r_contact_uri );
        $packet{ack} =~ s{^(ACK\s+)(\S+)(\s+SIP/2\.0)}
                         {$1 . $r_contact_uri . $3}eim;
    }

    last if $opt{limit} eq 1; # we sent one packet, we received one packet.

    next if $sl =~ /\s+1\d{2}\s+/; # info only

    my $resp;

    debug( "sl is: ", $sl );
    if( $sl =~ /\s+401 Unauthorized/i ){
        debug( "got 401 unauthorized" );
        my($realm,$nonce);
        if( $pkt =~ /^WWW-Authenticate: (.+)/im ){
            my $line = $1;
            debug( "found WWW-Authenticate: ", $line );
            if( $line =~ /realm="([^"]+)"/i ){
                $realm = $1;
                debug( "caught realm: ", $realm );
            }
            if( $line =~ /nonce="([^"]+)"/i ){
                $nonce = $1;
                debug( "caught nonce: ", $nonce );
            }
        }

        if( $realm && $nonce ){
            my $HA1 = md5_hex( "$opt{username}:$realm:$opt{password}" );
            my $HA2 = md5_hex( "INVITE:$opt{ruri}" );
            my $response = md5_hex( "$HA1:$nonce:$HA2" );

            my $invite = join("\n", @bare_invite) . "\n" . <<__EOAUTH__;
Authorization: Digest username="$opt{username}",
                  realm="$realm",
                  nonce="$nonce",
                  uri="$opt{ruri}",
                  response="$response",
                  algorithm=MD5
__EOAUTH__
            ;

            $invite .= "\n" .
                       $sdp . "\n";

            $packet{invite} = $invite;

            # increment cseq on all packets
            for my $type (keys %packet){
                # QQQ ack needs to be incremented on purpose here, would not have
                $packet{$type} =~ s/^(CSeq:\s*)(\d+)(\s+\w+)/$1 . ($2+1) . $3/mei;
            }

            $packet{invite} =~ s/\x0D?\x0A/\x0D\x0A/g;

            $resp = 'invite';
        }else{
            $resp = 'cancel';
        }
    }

    unless( $resp ){
        if( $sl =~ /^SIP\/2.0\s+[23456]\d{2}\s+/i && $sl !~ /\s+407\s+/){ 
            $resp = 'ack';
        }elsif( $sl =~ /^BYE/i ){
            $resp = 'ok';
        }else{
            $resp = 'cancel';
        }
    }

    $tx++;
    debug( "**** TX [$tx] $myhost:$myport -> $peerhost:$peerport\n",
           "--- \n",
           $packet{$resp},
           "--- " );
    $sock->send($packet{$resp}) or die "$resp send error: $!\n";

    exit if $sl =~ /^BYE/i;

    $loop++;
}

sub verbose {
    my ($msg) = join('', @_);
    warn "$msg\n";
}

sub debug {
    verbose @_ if $opt{debug};
}
