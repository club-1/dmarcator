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
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/emersion/go-milter"
)

func setup(t *testing.T, config string) (string, string, *bytes.Buffer) {
	tmp := t.TempDir()

	// setup logger
	prevLogOut := l.Writer()
	t.Cleanup(func() { l.SetOutput(prevLogOut) })
	r, w := io.Pipe()
	l.SetOutput(w)

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

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		main()
		wg.Done()
	}()
	t.Cleanup(func() {
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
		wg.Wait()
	})

	listener := readListener(t, r)
	buf := &bytes.Buffer{}
	l.SetOutput(buf)
	network, address, _ := strings.Cut(listener, "://")

	return network, address, buf
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
			testHeaders(t, config, []string{"Authentication-Results", c.header}, c.action)
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
	testHeaders(t, config, []string{"Authentication-Results", header}, expected)
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
	testHeaders(t, config, []string{"Authentication-Results", header}, expected)
}

func TestMultipleFields(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
		action  *milter.Action
		output  []string
	}{
		{
			name: "non authres header fields",
			headers: []string{
				"From", "hello@example.com",
				"Subject", "Hello world!",
			},
			action: &milter.Action{Code: milter.ActAccept},
			output: []string{`accept dmarc=unknown from=unknown addr="hello@example.com"`},
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
			output: []string{`reject dmarc=fail from=gmail.com addr=""`},
		},
		{
			name: "from bare address",
			headers: []string{
				"Authentication-Results", "mail.club1.fr; dmarc=pass header.from=gmail.com",
				"From", "coucou@gmail.com",
			},
			action: &milter.Action{Code: milter.ActAccept},
			output: []string{`accept dmarc=pass from=gmail.com addr="coucou@gmail.com"`},
		},
		{
			name: "from mime encoded address",
			headers: []string{
				"Authentication-Results", "mail.club1.fr; dmarc=pass header.from=coucou.fr",
				"From", "=?ISO-8859-1?Q?Aur=E9lien_COUDERC?= <libre@coucou.fr>",
			},
			action: &milter.Action{Code: milter.ActAccept},
			output: []string{`accept dmarc=pass from=coucou.fr addr="Aurélien COUDERC <libre@coucou.fr>"`},
		},
		{
			name: "from broken mime encoded",
			headers: []string{
				"Authentication-Results", "mail.club1.fr; dmarc=pass header.from=broken.com",
				"From", "=?UTF-42?Q?Broken?= <coucou@broken.com>",
			},
			action: &milter.Action{Code: milter.ActAccept},
			output: []string{`accept dmarc=pass from=broken.com addr="=?UTF-42?Q?Broken?= <coucou@broken.com>"`},
		},
		{
			name: "multiple from",
			headers: []string{
				"Authentication-Results", "mail.club1.fr; dmarc=pass header.from=gmail.com",
				"From", "first@gmail.com",
				"From", "second@gmail.com",
			},
			action: &milter.Action{Code: milter.ActAccept},
			output: []string{`accept dmarc=pass from=gmail.com addr="first@gmail.com"`},
		},
		{
			name: "more fields than needed",
			headers: []string{
				"Authentication-Results", "mail.club1.fr; dmarc=pass header.from=gmail.com",
				"From", "Coucou <coucou@gmail.com>",
				"Subject", "Hello world!",
			},
			action: &milter.Action{Code: milter.ActAccept},
			output: []string{`accept dmarc=pass from=gmail.com addr="Coucou <coucou@gmail.com>"`},
		},
	}
	config := `
ListenURI = "tcp://127.0.0.1:"
AuthservID = "mail.club1.fr"
RejectDomains = ["gmail.com"]
`
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testHeaders(t, config, c.headers, c.action, c.output...)
		})
	}
}

func testHeaders(t *testing.T, config string, headers []string, expectedAct *milter.Action, expectedOut ...string) {
	if len(headers)%2 != 0 {
		panic("headers varargs must be pairs")
	}
	network, address, out := setup(t, config)

	client := milter.NewClientWithOptions(network, address, milter.ClientOptions{
		Dialer: &net.Dialer{},
	})
	defer client.Close()
	session, err := client.Session()
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	defer session.Close()

	// Send a dummy MAIL FROM, without authentication macro.
	res, err := session.Mail("nicolas@example.fr", []string{})
	if err != nil {
		t.Fatal("unexpected err sending MAIL FROM: ", err)
	}
	if !reflect.DeepEqual(&milter.Action{Code: milter.ActContinue}, res) {
		t.Fatalf("expected %#v, got %#v", expectedAct, res)
	}

	if err := session.Macros(milter.CodeHeader, "i", "QUEUEID"); err != nil {
		t.Fatal("unexpected err setting queue id macro: ", err)
	}
	for i := 0; i < len(headers); i += 2 {
		_, err := session.HeaderField(headers[i], headers[i+1])
		if err != nil {
			t.Error("unexpected err sending header: ", err)
		}
	}
	res, err = session.HeaderEnd()
	if err != nil {
		t.Error("unexpected err sending EOH: ", err)
	}
	if !reflect.DeepEqual(res, expectedAct) {
		t.Errorf("expected %#v, got %#v", expectedAct, res)
	}
	for _, expected := range expectedOut {
		if !bytes.Contains(out.Bytes(), []byte(expected)) {
			t.Errorf("expected contains:\n%s\nactual:\n%s", expected, out.String())
		}
	}

	// Assert all log lines are prefixed with the queue ID.
	expectedPrefix := "QUEUEID:"
	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := string(scanner.Bytes())
		if !strings.HasPrefix(line, expectedPrefix) {
			t.Errorf("expected log lines to be prefixed with: %q\nactual:\n%s", expectedPrefix, line)
		}
	}
}

func TestAuthenticatedClient(t *testing.T) {
	config := `ListenURI = "tcp://127.0.0.1:"`
	network, address, out := setup(t, config)

	client := milter.NewClientWithOptions(network, address, milter.ClientOptions{
		Dialer: &net.Dialer{},
	})
	defer client.Close()
	session, err := client.Session()
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	defer session.Close()

	if err := session.Macros(milter.CodeMail, "{auth_authen}", "nicolas"); err != nil {
		t.Fatal("unexpected err setting auth macro: ", err)
	}
	res, err := session.Mail("nicolas@example.fr", []string{})
	if err != nil {
		t.Error("unexpected err sending MAIL FROM: ", err)
	}
	expectedAct := &milter.Action{Code: milter.ActAccept}
	if !reflect.DeepEqual(expectedAct, res) {
		t.Errorf("expected %#v, got %#v", expectedAct, res)
	}

	if out.Len() != 0 {
		t.Errorf("expected empty log output, got %q", out.String())
	}
}
