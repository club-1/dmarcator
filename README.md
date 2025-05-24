dmarcator
==========

Milter server that rejects mails based on the DMARC Authentication-Results
header added by a previous milter (e.g. OpenDMARC).

Some large mail providers (at least gmail.com) have a valid DMARC setup, but
use the `p=none` policy. This makes it completely useless for servers that
follow the specification, thus allowing scamers to spoof them very easily.

Common milter servers like OpenDMARC will not reject such mails, but will add
an Authentication-Results header with the result `dmarc=fail`. So dmarcator
simply reads this header and chooses to reject the mail despite the `p=none`
policy.

TODO
----

- [x] Make it configurable
- [x] Make it log to the syslog
- [x] Add a systemd unit
- [ ] Make a Debian package
