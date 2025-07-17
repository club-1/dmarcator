dmarcator
==========

[![build][build-svg]][build-url] [![coverage][cover-svg]][cover-url]

Milter server that rejects mails based on the DMARC Authentication-Results
header added by a previous milter (e.g. OpenDMARC).

Some large mail providers (at least gmail.com) have a valid DMARC setup, but
use the `p=none` policy. This makes it completely useless for servers that
follow the specification, thus allowing scamers to spoof them very easily.

Common milter servers like OpenDMARC will not reject such mails, but will add
an Authentication-Results header with the result `dmarc=fail`. So dmarcator
simply reads this header and chooses to reject the mail despite the `p=none`
policy.

See also [this forum thread (in French)](https://forum.club1.fr/d/245) for
more information about why this was created.

Configuration with Postfix on Debian
------------------------------------

A Debian package can be built from source based the [Debian packaging repo].

Postfix is run in a chroot in Debian, so it is needed to adapt the default
configuration. Create a new directory for the UNIX socket in Postfix's chroot
with the correct permissions, for example with systemd-tmpfiles:

```ini
#/etc/tmpfiles.d/dmarcator.conf
#Type  Path                          Mode  User       Group    Age  Argument
d      /var/spool/postfix/dmarcator  0750  dmarcator  postfix  -    -
```

Then:

    sudo systemd-tmpfiles --create

Set the ListenURI in dmarcator's config file, and by the way, set the list of rejected domains:

```toml
# /etc/dmarcator.conf
ListenURI = "unix:///var/spool/postfix/dmarcator/dmarcator.sock"

RejectDomains = [
	# Add the domains you want to reject if they fail DMARC, for example:
	"gmail.com",
	"hotmail.fr",
]
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

Checking the configuration
--------------------------

An easy way to check that the configuration is correct is by using
<https://dmarc-tester.com/>. Here is an excerpt of the syslog's mail facility
logs:

```
policyd-spf[1870138]: : prepend Authentication-Results: mail.club1.fr; spf=pass (sender SPF authorized) smtp.mailfrom=mg.spoofing.science (client-ip=69.72.42.6; helo=m42-6.mailgun.net; envelope-from=bounce+5cff61.3a5c1a-***=club1.fr@mg.spoofing.science; receiver=club1.fr)
postfix/smtpd[1869643]: 67A7541757: client=m42-6.mailgun.net[69.72.42.6]
postsrsd[1870162]: srs_forward: <bounce+5cff61.3a5c1a-***=club1.fr@mg.spoofing.science> rewritten as <SRS0=tNxH=YJ=mg.spoofing.science=bounce+5cff61.3a5c1a-***=club1.fr@club1.fr>
postsrsd[1870162]: srs_forward: <SRS0=tNxH=YJ=mg.spoofing.science=bounce+5cff61.3a5c1a-***=club1.fr@club1.fr> not rewritten: Valid SRS address for <bounce+5cff61.3a5c1a-***=club1.fr@mg.spoofing.science>
postfix/cleanup[1870161]: 67A7541757: message-id=<20250525152800.f2853f3b745eb0af@mg.spoofing.science>
opendkim[1175]: 67A7541757: DKIM verification successful
opendkim[1175]: 67A7541757: s=mx d=mg.spoofing.science a=rsa-sha256 SSL-
opendmarc[1151]: 67A7541757: gmail.com fail
dmarcator[1852753]: 67A7541757: reject dmarc=fail from=gmail.com
postfix/cleanup[1870161]: 67A7541757: milter-reject: END-OF-MESSAGE from m42-6.mailgun.net[69.72.42.6]: 5.7.1 rejected because of DMARC failure for gmail.com overriding policy; from=<SRS0=tNxH=YJ=mg.spoofing.science=bounce+5cff61.3a5c1a-***=club1.fr@club1.fr> to=<***@club1.fr> proto=ESMTP helo=<m42-6.mailgun.net>
```

[build-svg]: https://github.com/club-1/dmarcator/actions/workflows/build.yml/badge.svg
[build-url]: https://github.com/club-1/dmarcator/actions/workflows/build.yml
[cover-svg]: https://github.com/club-1/dmarcator/wiki/coverage.svg
[cover-url]: https://raw.githack.com/wiki/club-1/dmarcator/coverage.html
