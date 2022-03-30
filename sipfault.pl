#!/usr/bin/perl

# listen on 5060/udp
# respond to INVITE or OPTIONS with 404 or 503

use strict;
use Getopt::Long;
use IO::Socket::INET;

my %opt;
GetOptions( \%opt, 'Debug',
                   'localport=i',
                   'code=i',
          );

$opt{localport} ||= 5060;
$opt{code} ||= 404;


my $socket = IO::Socket::INET->new(
    LocalPort => $opt{localport},
    Proto => 'udp',
    ReuseAddr => 1,
) or die "cannot liston on socket: $!\n";

LOOP: while(1){

    # assume the header fits in 1472 bytes
    $socket->recv(my $data,1472);
    
    debug( "RX from ", $socket->peerhost(), ":", $socket->peerport() );
    debug( $data );

    my @rx_packet = (split /\r?\n/, $data);
    next LOOP unless $rx_packet[0] =~ /^(?:INVITE|OPTIONS)/;

    my $n;
    my @response;
    for my $line (@rx_packet){
        if( $line =~ /^Content-Length:/ ){
            push @response, "Content-Length: 0";
        }else{
            push @response, $line if $n; # drop the first line SIP/2.0 INVITE...
        }
        $n++;
    }

    debug();

    my $r = "SIP/2.0 ";
    $r .= $opt{code} eq '404' ? "404 Not Found" : "503 Service Unavailable";
    my @packet = ($r);
    push @packet, @response;

    my $return;
    for my $line (@packet){
        last if $line =~ /^\s*$/; # dont include the body

        $return .= $line . "\r\n";
    }

    debug( "TX:" );
    debug( $return );

    $socket->send($return) or die "packet tx error: $!\n";
}

sub verbose {
    my($msg) = join('', @_);

    warn "$msg\n";
}

sub debug {
    verbose @_ if $opt{Debug};
}
