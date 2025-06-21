// dmarcator, a milter server to reject mails based on DMARC headers
//
// Copyright (C) 2025  Nicolas Peugnet <nicolas@club1.fr>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/emersion/go-milter"
	"github.com/emersion/go-msgauth/authres"
)

type Conf struct {
	AuthservID    string
	ListenURI     string
	RejectDomains []string
	RejectFmt     string
	UMask         int
}

// Default values
var conf = Conf{
	ListenURI: "unix:///run/dmarcator/dmarcator.sock",
	RejectFmt: "rejected because of DMARC failure for %s overriding policy",
	UMask:     0o002,
}

// Set by the compiler
var version = "unknown"

var rejectDomains = make(map[string]bool)

var l *log.Logger = log.New(os.Stderr, "", 0)

const (
	fieldAuthres = 1 << iota
	fieldFrom

	// Keep last
	fieldLast
	fieldAll = fieldLast - 1
)

type Session struct {
	milter.NoOpMilter
	fieldsFound  uint
	dmarcResult  *authres.DMARCResult
	shouldReject bool
	headerFrom   string
}

func shouldRejectDMARCRes(result *authres.DMARCResult) bool {
	return result.Value != authres.ResultPass &&
		rejectDomains[strings.ToLower(result.From)]
}

func newRejectResponse(domain string) milter.Response {
	return milter.NewResponseStr(byte(milter.ActReplyCode), "550 5.7.1 "+fmt.Sprintf(conf.RejectFmt, domain))
}

func (s *Session) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	// Skip emails from authenticated clients, e.g. SASL authenticated in Postfix.
	if m.Macros["{auth_authen}"] != "" {
		return milter.RespAccept, nil
	}
	return milter.RespContinue, nil
}

func (s *Session) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	if s.fieldsFound == fieldAll {
		return milter.RespContinue, nil
	}

	if s.fieldsFound&fieldFrom == 0 && strings.EqualFold(name, "From") {
		s.fieldsFound |= fieldFrom
		s.headerFrom = value
		return milter.RespContinue, nil
	}

	if s.fieldsFound&fieldAuthres == 0 && strings.EqualFold(name, "Authentication-Results") {
		queueID := m.Macros["i"]
		id, results, err := authres.Parse(value)
		if err != nil {
			// Simply log in case we can't parse an AR header, because we cannot
			// handle it better than that.
			l.Printf("%s: failed to parse header: %v: %q", queueID, err, name+": "+value)
			return milter.RespContinue, nil
		}

		if !strings.EqualFold(id, conf.AuthservID) {
			// Not our Authentication-Results, ignore the field
			return milter.RespContinue, nil
		}

		for _, result := range results {
			if r, ok := result.(*authres.DMARCResult); ok {
				s.fieldsFound |= fieldAuthres
				s.dmarcResult = r
				s.shouldReject = shouldRejectDMARCRes(r)
			}
		}
	}

	return milter.RespContinue, nil
}

func (s *Session) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	queueID := m.Macros["i"]
	if s.dmarcResult == nil {
		l.Printf("%s: accept dmarc=unknown from=unknown addr=%q", queueID, s.headerFrom)
		return milter.RespAccept, nil
	}
	r := s.dmarcResult
	if s.shouldReject {
		l.Printf("%s: reject dmarc=%v from=%s addr=%q", queueID, r.Value, r.From, s.headerFrom)
		return newRejectResponse(r.From), nil
	} else {
		l.Printf("%s: accept dmarc=%v from=%s addr=%q", queueID, r.Value, r.From, s.headerFrom)
		return milter.RespAccept, nil
	}
}

const (
	usageFmt = `Usage: dmarcator [OPTION]...

Milter server that rejects mails based on the DMARC Authentication-Results
header added by a previous milter (e.g. OpenDMARC).

Options:
  -c FILE       Read config from FILE. (default %q)
  -h, --help    Show this help and exit.
  --version     Show version and exit.
`
	flagConfDef = "/etc/dmarcator.conf"
)

func main() {
	cli := flag.NewFlagSet("dmarcator", flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), usageFmt, flagConfDef)
	}
	var (
		flagConf    string
		flagHelp    bool
		flagVersion bool
	)
	cli.StringVar(&flagConf, "c", flagConfDef, "")
	cli.BoolVar(&flagHelp, "h", false, "")
	cli.BoolVar(&flagHelp, "help", false, "")
	cli.BoolVar(&flagVersion, "version", false, "")
	cli.Parse(os.Args[1:])

	if flagHelp {
		cli.SetOutput(os.Stdout)
		cli.Usage()
		os.Exit(0)
	}

	if flagVersion {
		fmt.Println("dmarcator", version)
		os.Exit(0)
	}

	conffile, err := os.Open(flagConf)
	if err != nil {
		l.Fatal("Failed to open conf file: ", err)
	}
	decoder := toml.NewDecoder(conffile)
	if _, err := decoder.Decode(&conf); err != nil {
		l.Fatalf("Failed to parse conf file %s: %v", flagConf, err)
	}

	if conf.AuthservID == "" {
		var err error
		conf.AuthservID, err = os.Hostname()
		if err != nil {
			l.Fatal("Failed to read hostname: ", err)
		}
	}

	network, address, found := strings.Cut(conf.ListenURI, "://")
	if !found {
		l.Fatal("Invalid listen URI")
	}

	for _, domain := range conf.RejectDomains {
		rejectDomains[strings.ToLower(domain)] = true
	}

	s := milter.Server{
		NewMilter: func() milter.Milter {
			return &Session{}
		},
		Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo | milter.OptNoBody,
	}

	// Allows to set the permissions of the created unix socket
	syscall.Umask(conf.UMask)

	ln, err := net.Listen(network, address)
	if err != nil {
		l.Fatal("Failed to setup listener: ", err)
	}

	// Closing the listener will unlink the unix socket, if any
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if err := s.Close(); err != nil {
			l.Fatal("Failed to close server: ", err)
		}
	}()

	l.Printf("Milter listening at %s://%v", ln.Addr().Network(), ln.Addr())
	if err := s.Serve(ln); err != nil && err != milter.ErrServerClosed {
		l.Fatal("Failed to serve: ", err)
	}
}
