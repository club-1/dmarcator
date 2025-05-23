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
// along with this program; if not, see
// <https://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/emersion/go-milter"
	"github.com/emersion/go-msgauth/authres"
)

var (
	// TODO: make these variables configurable, maybe based on a TOML config file?
	identity      string   = "mail.club1.fr"
	listenURI     string   = "unix:///var/spool/postfix/dmarc-reject/dmarc-reject.sock"
	rejectDomains []string = []string{"gmail.com"}
	rejectFmt     string   = "5.7.1 rejected because of DMARC failure for %s despite p=none"
)

type Session struct {
	milter.NoOpMilter
}

func shouldRejectDMARCRes(result *authres.DMARCResult) bool {
	if result.Value == authres.ResultPass {
		return false
	}
	if !slices.Contains(rejectDomains, result.From) {
		return false
	}
	return true
}

func newRejectResponse(domain string) milter.Response {
	return milter.NewResponseStr(byte(milter.ActReplyCode), "550 "+fmt.Sprintf(rejectFmt, domain))
}

func (s *Session) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	if !strings.EqualFold(name, "Authentication-Results") {
		return milter.RespContinue, nil
	}
	id, results, err := authres.Parse(value)
	if err != nil {
		// simply log in case we can't parse, an AR header, because we cannot
		// handle it better than that.
		log.Printf("failed to parse header: %v:\n%v: %v", err, name, value)
		return milter.RespContinue, nil
	}

	if !strings.EqualFold(id, identity) {
		// Not our Authentication-Results, ignore the field
		return milter.RespContinue, nil
	}

	for _, result := range results {
		if r, ok := result.(*authres.DMARCResult); ok {
			if shouldRejectDMARCRes(r) {
				return newRejectResponse(r.From), nil
			}
		}
	}

	return milter.RespContinue, nil
}

func main() {
	if identity == "" {
		var err error
		identity, err = os.Hostname()
		if err != nil {
			log.Fatal("Failed to read hostname: ", err)
		}
	}

	parts := strings.SplitN(listenURI, "://", 2)
	if len(parts) != 2 {
		log.Fatal("Invalid listen URI")
	}
	listenNetwork, listenAddr := parts[0], parts[1]

	s := milter.Server{
		NewMilter: func() milter.Milter {
			return &Session{}
		},
		Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoMailFrom | milter.OptNoRcptTo | milter.OptNoEOH | milter.OptNoBody,
	}

	ln, err := net.Listen(listenNetwork, listenAddr)
	if err != nil {
		log.Fatal("Failed to setup listener: ", err)
	}

	// Closing the listener will unlink the unix socket, if any
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if err := s.Close(); err != nil {
			log.Fatal("Failed to close server: ", err)
		}
	}()

	log.Println("Milter listening at", listenURI)
	if err := s.Serve(ln); err != nil && err != milter.ErrServerClosed {
		log.Fatal("Failed to serve: ", err)
	}
}
