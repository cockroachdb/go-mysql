package main

import (
	"fmt"
	"net"

	"github.com/go-mysql-org/go-mysql/proxy"
	"github.com/go-mysql-org/go-mysql/server"
)

func main() {
	l, _ := net.Listen("tcp", "127.0.0.1:1234")
	fmt.Println("waiting for connection")
	for {
		c, _ := l.Accept()
		fmt.Println("got connection")
		fmt.Println(c.LocalAddr(), c.RemoteAddr())
		go func() {
			mysql, _ := net.Dial("tcp", "insert AWS conn string")
			authConn, err := proxy.NewProxyConn(c, mysql, server.EmptyHandler{})
			if err != nil {
				panic(err)
			}

			fmt.Println("before handle conn loop")
			for {
				err := authConn.HandleCommand()
				if err != nil {
					panic(err)
				}
				fmt.Println("handled successfully")
			}
		}()
	}
}
