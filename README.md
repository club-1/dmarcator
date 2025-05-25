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

Configuration with Postfix on Debian
------------------------------------

A Debian package can be built from source based the [Debian packaging repo].

Postfix is run in a chroot in Debian, so it is needed to adapt the default
configuration. Create a new directory for the UNIX socket in Postfix's chroot
with the correct permissions, for example with systemd-tmpfiles:

```ini
#/etc/tmpfiles.d/dmarcator.conf
#Type Path                                    Mode User      Group   Age Argument
d     /var/spool/postfix/dmarcator            0750 dmarcator postfix -   -
```

Then:

    sudo systemd-tmpfiles --create

Set the ListenURI in dmarcator's config file:

```toml
# /etc/dmarcator.conf
ListenURI = "unix:///var/spool/postfix/dmarcator/dmarcator.sock"
```

Add dmarcator to postfix's milters in `/etc/postfix/main.cf`:

```diff
 smtpd_milters =
   local:opendkim/opendkim.sock
   local:opendmarc/opendmarc.sock
+  local:dmarcator/dmarcator.sock
```

Add postfix to the dmarcator group:

    sudo adduser postfix dmarcator

And finally restart both services:

    sudo systemctl restart postfix dmarcator

[Debian packaging repo]: https://salsa.debian.org/go-team/packages/dmarcator
