/*
* Honeytrap
* Copyright (C) 2016-2017 DutchSec (https://dutchsec.com/)
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU Affero General Public License version 3 as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
* details.
*
* You should have received a copy of the GNU Affero General Public License
* version 3 along with this program in the file "LICENSE".  If not, see
* <http://www.gnu.org/licenses/agpl-3.0.txt>.
*
* See https://honeytrap.io/ for more details. All requests should be sent to
* licensing@honeytrap.io
*
* The interactive user interfaces in modified source and object code versions
* of this program must display Appropriate Legal Notices, as required under
* Section 5 of the GNU Affero General Public License version 3.
*
* In accordance with Section 7(b) of the GNU Affero General Public License version 3,
* these Appropriate Legal Notices must retain the display of the "Powered by
* Honeytrap" logo and retain the original copyright notice. If the display of the
* logo is not reasonably feasible for technical reasons, the Appropriate Legal Notices
* must display the words "Powered by Honeytrap" and retain the original copyright notice.
 */
package smtp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

const loopTreshold = 100

type conn struct {
	rwc    net.Conn
	Text   *textproto.Conn
	domain string
	msg    *Message
	server *Server
	rcv    chan string
	i      int
	authed bool
}

func (c *conn) newMessage() *Message {

	return &Message{
		To:         []*mail.Address{},
		Body:       &bytes.Buffer{},
		Buffer:     &bytes.Buffer{},
		Domain:     c.domain,
		RemoteAddr: c.RemoteAddr().String(),
	}
}

func (c *conn) RemoteAddr() net.Addr {
	return c.rwc.RemoteAddr()
}

type stateFn func(c *conn) stateFn

func (c *conn) PrintfLine(format string, args ...interface{}) error {
	fmt.Printf("< ")
	fmt.Printf(format, args...)
	fmt.Println("")
	return c.Text.PrintfLine(format, args...)
}

func (c *conn) ReadLine() (string, error) {
	s, err := c.Text.ReadLine()
	fmt.Printf("> ")
	fmt.Println(s)

	//send line to log channel
	c.rcv <- s

	return s, err
}

func startState(c *conn) stateFn {
	c.PrintfLine("220 %s", c.server.Banner)
	return helloState
}

func unrecognizedState(c *conn) stateFn {
	c.PrintfLine("500 unrecognized command")
	return loopState
}

func errorState(format string, args ...interface{}) stateFn {
	msg := fmt.Sprintf(format, args...)
	return func(c *conn) stateFn {
		c.PrintfLine("500 %s", msg)
		return nil
	}
}

func outOfSequenceState() stateFn {
	return func(c *conn) stateFn {
		c.PrintfLine("503 command out of sequence")
		return nil
	}
}

func authPlainState(msg string) stateFn {
	if msg == "" {
		return func(c *conn) stateFn {
			c.PrintfLine("334 ")
			msg, err := c.ReadLine()
			if err != nil {
				log.Error("[authPlainState] error: %s", err.Error())
				return authErrState
			}
			return authPlainState(msg)
		}
	}

	upb, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		log.Error("[authPlainState] error: %s", err.Error())
		return authErrState
	}

	var up []string
	for _, bs := range bytes.Split(upb, []byte{0}) {
		up = append(up, string(bs))
	}
	if len(up) < 3 {
		return authErrState
	}

	return func(c *conn) stateFn {
		a := func() bool {
			for _, u := range c.server.Users {
				if len(u) < 2 {
					continue
				}
				if up[1] == u[0] && up[2] == u[1] {
					return true
				}
			}

			return false
		}()
		if !a {
			return authFailedState
		}
		return authSuccesState
	}
}

func authLoginState(msg string) stateFn {
	if msg == "" {
		return func(c *conn) stateFn {
			c.PrintfLine("334 VXNlcm5hbWU6")
			u64, err := c.ReadLine()
			if err != nil {
				return authErrState
			}
			return authLoginState(u64)
		}
	}
	return func(c *conn) stateFn {
		u, err := base64.StdEncoding.DecodeString(msg)
		if err != nil {
			return authErrState
		}

		c.PrintfLine("334 UGFzc3dvcmQ6")
		p64, err := c.ReadLine()
		if err != nil {
			return authErrState
		}

		p, err := base64.StdEncoding.DecodeString(p64)
		if err != nil {
			return authErrState
		}

		a := func() bool {
			for _, user := range c.server.Users {
				if len(u) < 2 {
					continue
				}
				if string(u) == user[0] && string(p) == user[1] {
					return true
				}
			}

			return false
		}()
		if !a {
			return authFailedState
		}
		return authSuccesState
	}
}

func authCramMD5State() stateFn {
	return func(c *conn) stateFn {
		challenge := md5.New()
		challenge.Write([]byte(time.Now().Format(time.RFC3339)))

		cMsg := base64.StdEncoding.EncodeToString(challenge.Sum(nil))
		c.PrintfLine("334 %s", cMsg)

		line, err := c.ReadLine()
		if err != nil {
			return authErrState
		}

		msg, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return authErrState
		}

		parts := bytes.Split(msg, []byte(" "))
		if len(parts) < 2 {
			return authErrState
		}

		for _, secret := range c.server.Secrets {
			if len(secret) < 2 {
				continue
			}
			if secret[0] == string(parts[0]) {
				h := hmac.New(md5.New, []byte(secret[1]))
				s := make([]byte, 0, h.Size())
				h.Write(challenge.Sum(s))
				if fmt.Sprintf("%x", h.Sum(nil)) == string(parts[1]) {
					return authSuccesState
				}
			}
		}

		return authFailedState
	}
}

func authErrState(c *conn) stateFn {
	c.PrintfLine("454 4.7.0 Temporary authentication failure")
	return loopState
}

func authFailedState(c *conn) stateFn {
	c.PrintfLine("535 5.7.8 Authentication credentials invalid")
	c.authed = false
	return loopState

}

func authSuccesState(c *conn) stateFn {
	c.PrintfLine("235 2.7.0 Authentication Succeeded")
	c.authed = true
	return loopState

}

func authState(msg string) stateFn {
	ps := strings.Split(msg, " ")
	if len(ps) < 2 {
		return unrecognizedState
	}
	switch strings.ToUpper(ps[1]) {
	case "PLAIN":
		if len(ps) < 3 {
			return authPlainState("")
		}
		return authPlainState(ps[2])
	case "LOGIN":
		if len(ps) < 3 {
			return authLoginState("")
		}
		return authLoginState(ps[2])
	case "CRAM-MD5":
		return authCramMD5State()
	default:
		return unrecognizedState
	}
}

func isCommand(line string, cmd string) bool {
	return strings.HasPrefix(strings.ToUpper(line), cmd)
}

func mailFromState(c *conn) stateFn {
	line, err := c.ReadLine()
	if err != nil {
		log.Error("[mailFromState] error: %s", err.Error())
		return nil
	}

	if line == "" {
		return loopState
	}

	if isCommand(line, "RSET") {
		c.PrintfLine("250 Ok")

		c.msg = c.newMessage()
		return loopState
	} else if isCommand(line, "RCPT TO") {
		addr, _ := mail.ParseAddress(line[8:])

		c.msg.To = append(c.msg.To, addr)

		c.PrintfLine("250 Ok")
		return mailFromState
	} else if isCommand(line, "BDAT") {
		parts := strings.Split(line, " ")

		var count int64
		if count, err = strconv.ParseInt(parts[1], 10, 32); err != nil {
			return errorState("[bdat]: error %s", err)
		}

		if _, err = io.CopyN(c.msg.Buffer, c.Text.R, count); err != nil {
			return errorState("[bdat]: error %s", err)
		}

		last := (len(parts) == 3 && parts[2] == "LAST")
		if !last {
			c.PrintfLine("250 Ok")
			return mailFromState
		}

		hasher := sha1.New()
		if err := c.msg.Read(io.TeeReader(c.msg.Buffer, hasher)); err != nil {
			return errorState("[bdat]: error %s", err)
		}

		c.PrintfLine("250 Ok : queued as +%x", hasher.Sum(nil))

		serverHandler{c.server}.Serve(*c.msg)

		c.msg = c.newMessage()
		return loopState
	} else if isCommand(line, "DATA") {
		c.PrintfLine("354 Enter message, ending with \".\" on a line by itself")

		hasher := sha1.New()
		err := c.msg.Read(io.TeeReader(c.Text.DotReader(), hasher))
		if err != nil {
			return errorState("[data]: error %s", err)
		}

		c.PrintfLine("250 Ok : queued as +%x", hasher.Sum(nil))

		serverHandler{c.server}.Serve(*c.msg)

		c.msg = c.newMessage()
		return loopState
	} else {
		return unrecognizedState
	}
}

func loopState(c *conn) stateFn {
	line, err := c.ReadLine()
	if err != nil {
		log.Error("[loopState] error: %s", err.Error())
		return nil
	}

	if line == "" {
		return loopState
	}

	c.i++

	if c.i > loopTreshold {
		return errorState("Error: invalid.")
	}

	if isCommand(line, "MAIL FROM") {
		c.msg.From, _ = mail.ParseAddress(line[10:])
		c.PrintfLine("250 Ok")
		return mailFromState
	} else if isCommand(line, "STARTTLS") {
		c.PrintfLine("220 Ready to start TLS")

		if c.server.tlsConfig != nil {
			tlsConn := tls.Server(c.rwc, c.server.tlsConfig)

			if err := tlsConn.Handshake(); err != nil {
				log.Error("Error during tls handshake: %s", err.Error())
				return nil
			}

			c.Text = textproto.NewConn(tlsConn)
			return helloState
		}
		log.Error("TLS not available")
		return nil
	} else if isCommand(line, "AUTH") {
		if c.authed {
			return outOfSequenceState()
		}
		return authState(line)
	} else if isCommand(line, "RSET") {
		c.msg = c.newMessage()
		c.PrintfLine("250 Ok")
		return loopState
	} else if isCommand(line, "QUIT") {
		c.PrintfLine("221 Bye")
		return nil
	} else if isCommand(line, "NOOP") {
		c.PrintfLine("250 Ok")
		return loopState
	} else if strings.Trim(line, " \r\n") == "" {
		return loopState
	} else {
		return unrecognizedState
	}
}

func parseHelloArgument(arg string) (string, error) {
	domain := arg
	if idx := strings.IndexRune(arg, ' '); idx >= 0 {
		domain = arg[idx+1:]
	}
	if domain == "" {
		return "", fmt.Errorf("Invalid domain")
	}
	return domain, nil
}

func helloState(c *conn) stateFn {
	line, _ := c.ReadLine()

	if isCommand(line, "HELO") {
		domain, err := parseHelloArgument(line)
		if err != nil {
			return errorState(err.Error())
		}

		c.domain = domain
		c.msg.Domain = domain

		c.PrintfLine("250 Hello %s, I am glad to meet you", domain)
		return loopState
	} else if isCommand(line, "EHLO") {
		domain, err := parseHelloArgument(line)
		if err != nil {
			return errorState(err.Error())
		}

		c.domain = domain
		c.msg.Domain = domain

		c.PrintfLine("250-Hello %s", domain)
		c.PrintfLine("250-SIZE 35882577")
		c.PrintfLine("250-8BITMIME")
		c.PrintfLine("250-STARTTLS")
		c.PrintfLine("250-ENHANCEDSTATUSCODES")
		c.PrintfLine("250-PIPELINING")
		c.PrintfLine("250-CHUNKING")
		c.PrintfLine("250-AUTH PLAIN LOGIN CRAM-MD5")
		c.PrintfLine("250 SMTPUTF8")
		return loopState
	} else {
		return errorState("Before we shake hands it will be appropriate to tell me who you are.")
	}
}

func (c *conn) serve() {
	c.Text = textproto.NewConn(c.rwc)
	defer c.Text.Close()

	// todo add idle timeout here

	state := startState
	for state != nil {
		state = state(c)
	}
}
