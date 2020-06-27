package main

import (
	"fmt"
	"net"
	"os"
)

var (
	serverAddr = "127.0.0.1:9000"
)

type tcpServer struct {
	addr    *net.TCPAddr
	listner *net.TCPListener
}

type udpServer struct {
	addr *net.UDPAddr
	conn *net.UDPConn
}

func main() {
	/*
		var goServer tcpServer
		var err error
		goServer.addr, err = net.ResolveTCPAddr("tcp", serverAddr)
		srvErr(err)
		goServer.listner, err = net.ListenTCP("tcp", goServer.addr)
		defer goServer.listner.Close()
		srvErr(err)
	*/

	var goUServer udpServer
	var err error
	goUServer.addr, err = net.ResolveUDPAddr("udp", serverAddr)
	goUServer.conn, err = net.ListenUDP("udp", goUServer.addr)
	defer goUServer.conn.Close()
	srvErr(err)

	fmt.Println("Server start ...")
	/*
		for {
			tcpConn, err := goServer.listner.Accept()
			srvErr(err)

			fmt.Println("Client: established", tcpConn.RemoteAddr().String)

			// handle in threads
			go srvHandle(tcpConn)
		}
	*/

	for {
		srvHandle(goUServer.conn)
	}
}

func srvErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func srvHandle(conn *net.UDPConn) {
	buffer := make([]byte, 1500)

	// setup read timeout
	//conn.SetReadDeadline(time.Now().Add(time.Microsecond * 10))
	//nbytes, err := conn.Read(buffer)

	nbytes, rAddr, err := conn.ReadFromUDP(buffer)
	srvErr(err)

	if nbytes == 0 {
		return
	}

	// Handle DNS msg
	msg := new(dnsMsg)
	err = msg.decodeMsg(buffer)
	srvErr(err)

	err = msg.resolveMsg()
	srvErr(err)

	buffer, err = msg.encodeMsg()
	srvErr(err)

	// setup write timeout
	//conn.SetWriteDeadline(time.Now().Add(time.Microsecond * 10))
	//nbytes, err = conn.Write(buffer)
	_, err = conn.WriteToUDP(buffer, rAddr)
	srvErr(err)
}
