package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cockroachdb/errors"
	. "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	mysqlserver "github.com/go-mysql-org/go-mysql/server"
	"github.com/siddontang/go/hack"
)

type Conn struct {
	clientConn *packet.Conn
	serverConn *packet.Conn
}

func NewProxyConn(client, server net.Conn, h mysqlserver.Handler) (*mysqlserver.Conn, error) {
	c := packet.NewTLSConn(client)
	s := packet.NewTLSConn(server)

	authConn := Conn{clientConn: c, serverConn: s}
	err := authConn.handshake()
	if err != nil {
		return nil, err
	}
	c.ResetSequence()
	return mysqlserver.NewAuthedProxyConn(c, h), nil
}

func (c *Conn) handshake() error {
	for {
		mysqlPacket, err := c.forwardServerPacket()
		if err != nil {
			return err
		}
		if mysqlPacket[0] == MORE_DATE_HEADER {
			switch mysqlPacket[1] {
			case CACHE_SHA2_FAST_AUTH:
				mysqlPacket, err = c.forwardServerPacket()
				if err != nil {
					return err
				}
			case CACHE_SHA2_FULL_AUTH:
				if err = c.forwardClientPacket(); err != nil {
					return err
				}

				mysqlPacket, err = c.forwardServerPacket()
				if err != nil {
					return err
				}
			default:
				return errors.AssertionFailedf("unknown packet header: %x", mysqlPacket[1])
			}
		}
		if mysqlPacket[0] == OK_HEADER {
			fmt.Println("got okay packet")
			return nil
		}

		if mysqlPacket[0] == ERR_HEADER {
			return c.handleErrorPacket(mysqlPacket)
		}

		err = c.forwardClientPacket()
		if err != nil {
			return err
		}
	}
}
func createTLSConfig(f *os.File, host string) (tls.Config, error) {
	rootCertPool := x509.NewCertPool()
	pem, err := os.ReadFile("/Users/jeremyyang/Downloads/us-east-1-bundle.pem")
	if err != nil {
		return tls.Config{}, err
	}
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return tls.Config{}, err
	}
	return tls.Config{
		RootCAs:            rootCertPool,
		ServerName:         host,
		InsecureSkipVerify: true,
	}, nil
}

func ServerTLSConfig() (*tls.Config, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	serverKey := filepath.Join(wd, "proxy", "server.key")
	serverCert := filepath.Join(wd, "proxy", "server.crt")
	cer, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, errors.Wrap(err, "error loading SSL certs")
	}

	return &tls.Config{Certificates: []tls.Certificate{cer}, InsecureSkipVerify: true}, nil
}

func (c *Conn) forwardClientPacket() error {
	clientPacket, err := c.clientConn.ReadPacket()
	if err != nil {
		return err
	}
	if bytes.Equal(clientPacket[9:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		// Switch to TLS
		if err = c.serverConn.WritePacket(append([]byte{0, 0, 0, 0}, clientPacket...)); err != nil {
			return err
		}

		temp, _ := createTLSConfig(nil, "insert aws host")

		tlsConn := tls.Client(c.serverConn.Conn, &temp)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}

		currentSequence := c.serverConn.Sequence
		c.serverConn = packet.NewConn(tlsConn)
		c.serverConn.Sequence = currentSequence

		certs, err := ServerTLSConfig()
		if err != nil {
			return err
		}
		tlsConnClient := tls.Server(c.clientConn.Conn, certs)
		// if err := tlsConnClient.Handshake(); err != nil {
		// 	return err
		// }
		c.clientConn.Conn = tlsConnClient

		fmt.Println("reading client packet")
		clientPacket, err = c.clientConn.ReadPacket()
		if err != nil {
			return errors.Wrap(err, "error after read in tls")
		}
		fmt.Printf("Client Packet: %x\n", clientPacket)
	}
	fmt.Println("Writing client packet to server")
	// TODO (migrations): Figure out byte allocation so we dont need
	// to do this allocation every packet write
	if err = c.serverConn.WritePacket(append([]byte{0, 0, 0, 0}, clientPacket...)); err != nil {
		return err
	}
	return nil
}

func (c *Conn) forwardServerPacket() ([]byte, error) {
	mysqlPacket, err := c.serverConn.ReadPacket()
	if err != nil {
		return nil, err
	}
	// TODO (migrations): Figure out byte allocation so we dont need
	// to do this allocation every packet write
	if err = c.clientConn.WritePacket(append([]byte{0, 0, 0, 0}, mysqlPacket...)); err != nil {
		return nil, err
	}
	return mysqlPacket, nil
}

func (c *Conn) handleErrorPacket(data []byte) error {
	e := new(MyError)

	var pos = 1

	e.Code = binary.LittleEndian.Uint16(data[pos:])
	pos += 2

	// Hack for now since we should be always dealing with
	// client_protocol_41
	//skip '#'
	pos++
	e.State = hack.String(data[pos : pos+5])
	pos += 5

	e.Message = hack.String(data[pos:])

	return e
}
