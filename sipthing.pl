#!/usr/bin/perl

# have crude sip conversation
# jkister 2021092701

use strict;
use IO::Socket;
use Getopt::Long;

my %opt;
GetOptions( \%opt, 'Debug',
                   'host=s',
                   'port=i',
                   'localport=i',
                   'from=s',
                   'fromname=s',
                   'to=s',
                   'useragent=s',
                   'mode=s',
                   'callid=s',
                   'branch=s',
                   'tag=s',
                   'fromhost=s',
                   'tohost=s',
                   'allow=s',
                   'quiet',
                   'pai',
                   'padding=i',
                   'identity=s',
                   'indicator=s',
                   'nocancel',
          );
                   
$opt{host}      || die "specify --host <host>\n";
$opt{port}      ||= 5060;
$opt{localport} ||= int(rand(55534)) + 10001;
$opt{from}      ||= 'sipthing';
$opt{fromname}  ||= $opt{from};
$opt{to}        ||= $opt{from};
$opt{useragent} ||= 'sipthing/0.51';
$opt{mode}      ||= 'options';
$opt{callid}    ||= join '', map { unpack 'H*', chr(rand(256)) } 1..16;
$opt{branch}    ||= join '', map { unpack 'H*', chr(rand(256)) } 1..16;
$opt{tag}       ||= join '', map { unpack 'H*', chr(rand(256)) } 1..8;
$opt{allow}     ||= 'INVITE, ACK, CANCEL, OPTIONS, BYE';

if( $opt{indicator} ){
    $opt{indicator} = uc($opt{indicator});
    die "bad indicator\n" unless $opt{indicator} =~ /^[ABC]$/;
}

$opt{mode} eq 'invite' || $opt{mode} eq 'options' || die "invalid --mode\n";

$|=1;
my $sock = IO::Socket::INET->new(PeerAddr  => $opt{host},
                                 PeerPort  => $opt{port},
                                 LocalPort => $opt{localport},
                                 ReuseAddr => 1,
                                 Proto     => 'udp',
                                ) or die "socket error: $!\n";

$sock->setsockopt(SOL_SOCKET, SO_RCVTIMEO, pack('l!l!', 5, 0)) or die "setsockopt: $!\n";

my $myport       = $sock->sockport();
my $myhost       = $sock->sockhost();
my $peerport     = $sock->peerport();
my $peerhost     = $sock->peerhost();
$opt{fromhost} ||= $myhost;
$opt{tohost}   ||= $peerhost;

my @dmap = qw/Sun Mon Tue Wed Thu Fri Sat/;
my @mmap = qw/Jan Feb Mar Arp May Jun Jul Aug Sep Oct Nov Dec/;
my ($sec,$min,$hour,$mday,$mon,$year,$wday) = (gmtime())[0,1,2,3,4,5,6];

my $date = sprintf('%s, %02d %s %04d %02d:%02d:%02d',
                   $dmap[$wday], $mday, $mmap[$mon],
                   ($year+1900),$hour,$min,$sec) . ' GMT';

my @options = split "\n", <<__EOO__;
OPTIONS sip:$opt{to}\@$peerhost:$peerport SIP/2.0
Via: SIP/2.0/UDP $myhost;branch=$opt{branch}
Contact: <sip:$opt{from}\@$myhost:$myport>
From: "$opt{fromname}" <sip:$opt{from}\@$myhost:$myport>;tag=$opt{tag}
To: <sip:$opt{to}\@$opt{tohost}:$peerport>
Call-ID: $opt{callid}\@$myhost:$myport
CSeq: 100 OPTIONS
User-Agent: $opt{useragent}
Date: $date
Allow: $opt{allow}
Content-Length: 0
__EOO__

if( $opt{padding} ){
    push @options, "X-Padding: " . 'A' x $opt{padding};
}
push @options, '';


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

my $length = length($sdp) + 12; # + for each line

my @invite = split "\n", <<__EOI__;
INVITE sip:$opt{to}\@$opt{tohost} SIP/2.0
Record-Route: <sip:$myhost;lr=on;ftag=as5b8a6f2b;did=9d4.566a0624>
Via: SIP/2.0/UDP $myhost:$myport;branch=$opt{branch}
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}>;tag=$opt{tag}
To: <sip:$opt{to}\@$opt{tohost}:$opt{port}>
Contact: <sip:$opt{from}\@$opt{fromhost}>
Call-ID: $opt{callid}\@$myhost:$myport
CSeq: 100 INVITE
User-Agent: $opt{useragent}
Max-Forwards: 69
Remote-Party-ID: "$opt{from}" <sip:$opt{from}\@$opt{fromhost}>;privacy=off;screen=no
Date: $date
Allow: $opt{allow}
Supported: replaces
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
    push @invite, "Via: SIP/2.0/UDP $opt{fromhost}:5060;received=$opt{fromhost};branch=$opt{branch};rport=5060";
}
if( $opt{padding} ){
    push @invite, "X-Padding: " . 'A' x $opt{padding};
}

push @invite, ('', split("\n", $sdp), '');

my $ok = <<__EOOK__;
SIP/2.0 200 OK sip:$opt{to}\@$peerhost SIP/2.0
Via: SIP/2.0/UDP $myhost:$myport;branch=$opt{branch}
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}>;tag=$opt{tag}
To: <sip:$opt{to}\@$opt{tohost}:$opt{port}>
Contact: <sip:$opt{from}\@$opt{fromhost}>
Call-ID: $opt{callid}\@$myhost:$myport
CSeq: 100 INVITE
User-Agent: $opt{useragent}
Content-Length: 0

__EOOK__

my $cancel = <<__EOCANCEL__;
CANCEL sip:$opt{to}\@$opt{tohost} SIP/2.0
Via: SIP/2.0/UDP $myhost:$myport;branch=$opt{branch}
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}>;tag=$opt{tag}
To: <sip:$opt{to}\@$opt{tohost}:$opt{port}>
Contact: <sip:$opt{from}\@$opt{fromhost}>
Call-ID: $opt{callid}\@$myhost:$myport
CSeq: 100 CANCEL
User-Agent: $opt{useragent}
Content-Length: 0


__EOCANCEL__

my $ack = <<__EOACK__;
ACK sip:$opt{to}\@$opt{tohost} SIP/2.0
Via: SIP/2.0/UDP $myhost:$myport;branch=$opt{branch}
From: "$opt{fromname}" <sip:$opt{from}\@$opt{fromhost}>;tag=$opt{tag}
To: <sip:$opt{to}\@$opt{tohost}:$opt{port}>
Call-ID: $opt{callid}\@$myhost:$myport
CSeq: 100 ACK
User-Agent: $opt{useragent}
Content-Length: 0

__EOACK__

my %packet = ( ack => $ack,
               ok  => $ok,
               cancel => $cancel,
             );

my $msg = $opt{mode} eq 'invite' ? join("\n", @invite) : join("\n", @options);
$msg =~ s/\x0D?\x0A/\x0D\x0A/g;

my $payload_size = length($msg);
my $total_size = $payload_size + 20 + 8; # + ip header + udp header

warn "**** TX $myhost:$myport -> $peerhost:$peerport\n",
     "***** with $total_size byte packet ($payload_size byte payload):\n",
     "--- \n",
     $msg,
     "--- \n" if $opt{Debug};

$sock->send($msg) or die "send error: $!\n";

$sock->recv(my $pkt, 4096) or die "Recv error: $!\n";
my $fl = (split /\r?\n/, $pkt)[0];
print "**** RX $peerhost:$peerport -> $myhost:$myport\n";
if( $opt{quiet} ){
    print "$fl\n";
}else{
    print "--- \n",
          $pkt,
          "--- \n";
}

exit if $opt{mode} eq 'options';

my $resp = ($fl =~ /3\d{2}/) ? 'ack' : 'ok';

warn "**** TX $myhost:$myport -> $peerhost:$peerport\n",
     "--- \n",
     $packet{$resp},
     "--- \n" if $opt{Debug};
$resp =~ s/\x0D?\x0A/\x0D\x0A/g;
$sock->send($resp) or die "ok send error: $!\n";


unless( $resp eq 'ack' || $opt{nocancel} ){
    warn "**** TX $myhost:$myport -> $peerhost:$peerport\n",
         "--- \n",
         $cancel,
         "--- \n" if $opt{Debug};

    $cancel =~ s/\x0D?\x0A/\x0D\x0A/g;
    $sock->send($cancel) or die "cancel send error: $!\n";
}

while (1) {
    $sock->timeout(1);
    if( $sock->recv(my $pkt, 4096) ){
        print "**** RX $peerhost:$peerport -> $myhost:$myport\n";
        if( $opt{quiet} ){
            my $fl = (split /\r?\n/, $pkt)[0];
            print "$fl\n";
        }else{
            print "--- \n",
                  $pkt,
                  "--- \n";
        }
    }else{
        last;
    }
}
