package auth

import (
	"encoding/binary"
	"net"

	. "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/siddontang/go/hack"
)

type Conn struct {
	clientConn *packet.Conn
	serverConn *packet.Conn
}

func NewProxyAuth(client, server net.Conn) *Conn {
	c := packet.NewConn(client)
	s := packet.NewConn(server)
	return &Conn{clientConn: c, serverConn: s}
}

func (c *Conn) InitiateAuth() error {
	for {
		mysqlPacket, err := c.forwardServerPacket()
		if err != nil {
			return err
		}

		if mysqlPacket[0] == OK_HEADER {
			return nil
		}
		if mysqlPacket[0] == ERR_HEADER {
			return c.handleErrorPacket(mysqlPacket)
		}

		if mysqlPacket[0] == MORE_DATE_HEADER {
			switch mysqlPacket[1] {
			case CACHE_SHA2_FAST_AUTH:
				mysqlPacket, err = c.forwardServerPacket()
				if err != nil {
					return err
				}
			case CACHE_SHA2_FULL_AUTH:
				err = c.forwardClientPacket()
				if err != nil {
					return err
				}

				mysqlPacket, err = c.forwardServerPacket()
				if err != nil {
					return err
				}
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

	err = c.serverConn.WritePacket(append([]byte{0, 0, 0, 0}, clientPacket...))
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) forwardServerPacket() ([]byte, error) {
	mysqlPacket, err := c.serverConn.ReadPacket()
	if err != nil {
		return nil, err
	}
	err = c.clientConn.WritePacket(append([]byte{0, 0, 0, 0}, mysqlPacket...))
	if err != nil {
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
