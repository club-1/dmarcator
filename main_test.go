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
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/emersion/go-milter"
)

func setup(t *testing.T, config string) *io.PipeReader {
	tmp := t.TempDir()

	// setup logger
	prevLogger := l
	t.Cleanup(func() { l = prevLogger })
	r, w := io.Pipe()
	l = log.New(w, "", 0)

	// setup config file
	configPath := filepath.Join(tmp, "dmarcator.conf")
	err := os.WriteFile(configPath, []byte(config), 0664)
	if err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"dmarcator", "-c", configPath}

	// save default conf
	prevConf := conf
	t.Cleanup(func() { conf = prevConf })

	return r
}

func readListener(t *testing.T, r io.Reader) string {
	scanner := bufio.NewScanner(r)
	read := &bytes.Buffer{}
	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.HasPrefix(line, []byte("Milter listening")) {
			return string(line[20:])
		}
		read.Write(line)
	}
	t.Fatalf("listener not found, err: %v, read:\n%s", scanner.Err(), read.Bytes())
	return ""
}

func TestHauthRes(t *testing.T) {
	cases := []struct {
		name   string
		header string
		action *milter.Action
	}{
		{
			name:   "pass for rejected domain",
			header: "mail.club1.fr; dmarc=pass header.from=gmail.com",
			action: &milter.Action{Code: milter.ActAccept},
		},
		{
			name:   "none for rejected domain",
			header: "mail.club1.fr; dmarc=none header.from=gmail.com",
			action: &milter.Action{
				Code:     milter.ActReplyCode,
				SMTPCode: 550,
				SMTPText: "5.7.1 rejected because of DMARC failure for gmail.com overriding policy",
			},
		},
		{
			name:   "fail for rejected domain",
			header: "mail.club1.fr; dmarc=fail header.from=gmail.com",
			action: &milter.Action{
				Code:     milter.ActReplyCode,
				SMTPCode: 550,
				SMTPText: "5.7.1 rejected because of DMARC failure for gmail.com overriding policy",
			},
		},
		{
			name:   "fail for rejected domain uppercase",
			header: "mail.club1.fr; dmarc=fail header.from=GMAIL.com",
			action: &milter.Action{
				Code:     milter.ActReplyCode,
				SMTPCode: 550,
				SMTPText: "5.7.1 rejected because of DMARC failure for GMAIL.com overriding policy",
			},
		},
		{
			name:   "fail for non-rejected domain",
			header: "mail.club1.fr; dmarc=fail header.from=example.com",
			action: &milter.Action{Code: milter.ActAccept},
		},
		{
			name:   "none for non-rejected domain",
			header: "mail.club1.fr; dmarc=none header.from=example.com",
			action: &milter.Action{Code: milter.ActAccept},
		},
		{
			name:   "non dmarc header",
			header: "mail.club1.fr; auth=none header.from=example.com",
			action: &milter.Action{Code: milter.ActAccept},
		},
		{
			name:   "results from other authserv-id",
			header: "example.com; dmarc=fail header.from=gmail.com",
			action: &milter.Action{Code: milter.ActAccept},
		},
		{
			name:   "invalid authentication-results header",
			header: "mail.club1.fr; dmarc header.from=gmail.com",
			action: &milter.Action{Code: milter.ActAccept},
		},
	}
	config := `
ListenURI = "tcp://127.0.0.1:"
AuthservID = "mail.club1.fr"
RejectDomains = ["gmail.com"]
`
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testHeaders(t, c.action, config, "Authentication-Results", c.header)
		})
	}
}

func TestConfigNoAuthservID(t *testing.T) {
	config := `
ListenURI = "tcp://127.0.0.1:"
RejectDomains = ["gmail.com"]
`
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	header := hostname + "; dmarc=fail header.from=gmail.com"
	expected := &milter.Action{
		Code:     milter.ActReplyCode,
		SMTPCode: 550,
		SMTPText: "5.7.1 rejected because of DMARC failure for gmail.com overriding policy",
	}
	testHeaders(t, expected, config, "Authentication-Results", header)
}

func TestUNIXSocket(t *testing.T) {
	config := `
ListenURI = "unix:///tmp/dmarcator.sock"
AuthservID = "mail.club1.fr"
RejectDomains = ["gmail.com"]
`
	header := "mail.club1.fr; dmarc=fail header.from=gmail.com"
	expected := &milter.Action{
		Code:     milter.ActReplyCode,
		SMTPCode: 550,
		SMTPText: "5.7.1 rejected because of DMARC failure for gmail.com overriding policy",
	}
	testHeaders(t, expected, config, "Authentication-Results", header)
}

func TestMultipleFields(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
		action  *milter.Action
	}{
		{
			name: "non authres header fields",
			headers: []string{
				"From", "hello@example.com",
				"Subject", "Hello world!",
			},
			action: &milter.Action{Code: milter.ActAccept},
		},
		{
			name: "multiple dmarc",
			headers: []string{
				"Authentication-Results", "mail.club1.fr; dmarc=fail header.from=gmail.com",
				"Authentication-Results", "mail.club1.fr; dmarc=pass header.from=gmail.com",
			},
			action: &milter.Action{
				Code:     milter.ActReplyCode,
				SMTPCode: 550,
				SMTPText: "5.7.1 rejected because of DMARC failure for gmail.com overriding policy",
			},
		},
		{
			name: "from bare address",
			headers: []string{
				"Authentication-Results", "mail.club1.fr; dmarc=pass header.from=gmail.com",
				"From", "coucou@gmail.com",
			},
			action: &milter.Action{Code: milter.ActAccept},
		},
	}
	config := `
ListenURI = "tcp://127.0.0.1:"
AuthservID = "mail.club1.fr"
RejectDomains = ["gmail.com"]
`
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testHeaders(t, c.action, config, c.headers...)
		})
	}
}

func testHeaders(t *testing.T, expected *milter.Action, config string, headers ...string) {
	if len(headers)%2 != 0 {
		panic("headers varargs must be pairs")
	}
	out := setup(t, config)
	go main()
	defer syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	l := readListener(t, out)
	network, address, _ := strings.Cut(l, "://")

	client := milter.NewClientWithOptions(network, address, milter.ClientOptions{
		Dialer: &net.Dialer{},
	})
	defer client.Close()
	session, err := client.Session()
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	defer session.Close()

	go io.Copy(io.Discard, out)
	for i := 0; i < len(headers); i += 2 {
		_, err := session.HeaderField(headers[i], headers[i+1])
		if err != nil {
			t.Error("unexpected err sending header: ", err)
		}
	}
	res, err := session.HeaderEnd()
	if err != nil {
		t.Error("unexpected err sending EOH: ", err)
	}
	if !reflect.DeepEqual(res, expected) {
		t.Errorf("expected %#v, got %#v", expected, res)
	}
}
