package auth

import (
	"encoding/binary"
	"net"

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
	c := packet.NewConn(client)
	s := packet.NewConn(server)

	authConn := Conn{clientConn: c, serverConn: s}
	err := authConn.handshake()
	if err != nil {
		return nil, err
	}
	return mysqlserver.NewAuthedProxyConn(client, h), nil
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

func (c *Conn) forwardClientPacket() error {
	clientPacket, err := c.clientConn.ReadPacket()
	if err != nil {
		return err
	}
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
