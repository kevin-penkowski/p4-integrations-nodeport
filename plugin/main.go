package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {

	// Construct a packet to send
	pkt := []byte{
		0x6c, 0x62, 0x6d, 0x50, 0xe6, 0xe4, 0x94, 0xde, 0x80, 0xa5, 0xec, 0x79, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x3c, 0x47, 0xd9, 0x40, 0x00, 0x40, 0x06, 0xb5, 0x94, 0xc0, 0xa8, 0x34, 0x7b, 0x36, 0xe7,
		0x11, 0x44, 0xc3, 0x66, 0x00, 0x50, 0x09, 0x58, 0x6b, 0xeb, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
		0x72, 0x10, 0x26, 0x38, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x0d, 0x3d,
		0x2c, 0x32, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
	}

	// Socket is defined as:
	// func Socket(domain, typ, proto int) (fd int, err error)
	// Domain specifies the protocol family to be used - this should be AF_PACKET
	// to indicate we want the low level packet interface
	// Type specifies the semantics of the socket
	// Protocol specifies the protocol to use - kept here as ETH_P_ALL to
	// indicate all protocols over Ethernet
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW,
		syscall.ETH_P_ALL) // ETH_P_ALL works for Linux/Unix so may show as undefined on Windows
	if err != nil {
		fmt.Println("Error1: " + err.Error())
		return
	}
	fmt.Println("Obtained fd ", fd)
	defer syscall.Close(fd)

	if_info, err := net.InterfaceByName("eth0")
	if err != nil {
		fmt.Println("Error2: " + err.Error())
	}

	var haddr [8]byte
	copy(haddr[0:7], if_info.HardwareAddr[0:7])
	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  if_info.Index,
		Halen:    uint8(len(if_info.HardwareAddr)),
		Addr:     haddr,
	}

	err = syscall.Bind(fd, &addr)
	if err != nil {
		fmt.Println("Error3: " + err.Error())
	}

	err = syscall.SetLsfPromisc("eth0", true)
	if err != nil {
		fmt.Println("Error4: " + err.Error())
	}

	n, err := syscall.Write(fd, pkt)
	if err != nil {
		fmt.Println("Error5: " + err.Error())
		fmt.Println(n)
	} else {
		fmt.Println("Packet is sent.")
		fmt.Println(n)
	}

	err = syscall.SetLsfPromisc("eth0", false)
	if err != nil {
		fmt.Println("Error6: " + err.Error())
	}

	syscall.Close(fd)
}
