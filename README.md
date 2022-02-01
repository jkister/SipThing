# SipThing

have crude sip conversation

use like:

# send options, expect reply
sipthing.pl --host 10.0.0.5

# send invite, have crude conversation
sipthing.pl --host 10.0.0.5 --mode invite --from 2155551212 --to 6105551212

# send invite, loading the invite from a file, have crude conversation
sipthing.pl --host 10.0.0.5 --mode invite --sipfile sip.txt


# use -D for printing debug info
