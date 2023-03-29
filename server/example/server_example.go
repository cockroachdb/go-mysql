package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/siddontang/go-log/log"
)

type RemoteThrottleProvider struct {
	*server.InMemoryProvider
	delay int // in milliseconds
}

func (m *RemoteThrottleProvider) GetCredential(
	username string,
) (password string, found bool, err error) {
	time.Sleep(time.Millisecond * time.Duration(m.delay))
	return m.InMemoryProvider.GetCredential(username)
}

func main() {
	l, _ := net.Listen("tcp", "127.0.0.1:1234")
	// user either the in-memory credential provider or the remote credential provider (you can implement your own)
	//inMemProvider := server.NewInMemoryProvider()
	//inMemProvider.AddUser("root", "123")
	remoteProvider := &RemoteThrottleProvider{server.NewInMemoryProvider(), 10 + 50}
	remoteProvider.AddUser("user", "password")
	// var tlsConf = server.NewServerTLSConfig(test_keys.CaPem, test_keys.CertPem, test_keys.KeyPem, tls.VerifyClientCertIfGiven)
	for {
		c, _ := l.Accept()
		// fmt.Println(c.LocalAddr(), c.RemoteAddr())
		// mysql, _ := net.Dial("tcp", ":3306")
		// go func() {
		// 	copied, err := io.Copy(mysql, c)
		// 	fmt.Println("done with go routine copy")
		// 	if err != nil {
		// 		fmt.Printf("Conection error: %s", err.Error())
		// 	}

		// 	fmt.Printf("Connection closed. Bytes copied: %d", copied)
		// }()

		// copied, err := io.Copy(c, mysql)
		// fmt.Println("done with copy")

		// if err != nil {
		// 	fmt.Printf("Connection error: %s", err.Error())
		// }

		// fmt.Printf("Connection closed. Bytes copied:  %d", copied)

		go func() {
			fmt.Println("inside here")
			// Create a connection with user root and an empty password.
			// You can use your own handler to handle command here.
			//svr := server.NewServer("8.0.12", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_NATIVE_PASSWORD, test_keys.PubPem, nil)
			// db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", "user", "password", "127.0.0.1", "defaultdb"))
			// if err != nil {
			// 	panic(err)
			// }
			// c, err := db.Conn(context.Background())
			// if err != nil {
			// 	panic(err)
			// }
			// mysql, err := client.Connect("127.0.0.1:3306", "user", "password", "defaultdb")
			// if err != nil {
			// 	panic(err)
			// }
			// mysql.Close()
			mysql, _ := net.Dial("tcp", "otan-mysql-test.cpa6lrp2ahsc.us-east-1.rds.amazonaws.com:3306")
			mysqlPacket := packet.NewConn(mysql)
			cclientPacket := packet.NewConn(c)

			// mysqlp, err := mysqlPacket.ReadPacket()
			// if err != nil {
			// 	panic(err)
			// }

			// err = cclientPacket.WritePacket(mysqlp)
			// if err != nil {
			// 	panic(err)
			// }
			// fmt.Println("after handshake")
			for {
				fmt.Println("in auth loop")

				mysqlp, err := mysqlPacket.ReadPacket()
				if err != nil {
					panic(err)
				}

				fmt.Println("after mysql read")

				err = cclientPacket.WritePacket(append([]byte{0, 0, 0, 0}, mysqlp...))
				if err != nil {
					panic(err)
				}
				fmt.Printf("mysqlread: %x\n", mysqlp)

				if mysqlp[0] == 1 {
					if mysqlp[1] == 3 {
						mysqlp, err = mysqlPacket.ReadPacket()
						if err != nil {
							panic(err)
						}

						fmt.Println("after mysql read")
						fmt.Printf("mysqlread: %x\n", mysqlp)
						err = cclientPacket.WritePacket(append([]byte{0, 0, 0, 0}, mysqlp...))
						if err != nil {
							panic(err)
						}
					}
				}

				if mysqlp[0] == 0 {
					fmt.Println("auth done")
					break
				}

				cp, err := cclientPacket.ReadPacket()
				if err != nil {
					panic(err)
				}
				fmt.Printf("client read: %x\n", cp)
				fmt.Println("after client handshake")

				err = mysqlPacket.WritePacket(append([]byte{0, 0, 0, 0}, cp...))
				if err != nil {
					panic(err)
				}
				fmt.Println("after mysql write")

			}
			// go func() {
			// 	copied, err := io.Copy(mysql, c)
			// 	fmt.Println("done with go routine copy")
			// 	if err != nil {
			// 		fmt.Printf("Conection error: %s", err.Error())
			// 	}

			// 	fmt.Printf("Connection closed. Bytes copied: %d\n", copied)
			// }()

			// copied, err := io.Copy(c, mysql)
			// fmt.Println("done with copy")

			// if err != nil {
			// 	fmt.Printf("Connection error: %s", err.Error())
			// }

			// packet.NewConn()
			// fmt.Printf("Connection closed. Bytes copied:  %d\n", copied)
			// NewConn writes the handshake so at this point the hand shake copied back was for the other mysql
			conn, err := server.NewConn(c, "user", "password", server.EmptyHandler{}, nil)
			//conn := &server.Conn{Conn: packet.NewConn(c), H: server.EmptyHandler{}}
			if err != nil {
				log.Errorf("Connection error: %v", err)
				return
			}

			for {
				err := conn.HandleCommand()
				if err != nil {
					log.Errorf(`Could not handle command: %v`, err)
					return
				}
				fmt.Println("handled successfully")
			}
		}()
	}
}

func createTLSConfig(filepath, host string) (tls.Config, error) {
	rootCertPool := x509.NewCertPool()
	pem, err := os.ReadFile(filepath)
	if err != nil {
		return tls.Config{}, err
	}
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return tls.Config{}, err
	}
	return tls.Config{
		RootCAs:    rootCertPool,
		ServerName: host,
	}, nil
}
