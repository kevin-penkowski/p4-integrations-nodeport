package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {

	// Construct a packet to send
	pkt := []byte{
		// Ethernet header = 14 bytes
		0x12, 0x65, 0x6b, 0x54, 0xCB, 0x90, // Destination MAC (12:65:6B:54:CB:90)
		0x16, 0x9b, 0x47, 0x4e, 0x47, 0x4c, // Source MAC (16:9B:47:4E:47:4C)
		0x08, 0x00, // Type = IP
		// IP header = 20 bytes
		0x45, 0x00, 0x00, 0x3c, // Version, IHL, TOS, Length
		0x47, 0xd9, 0x40, 0x00, // ID, Flags, Fragment Offset
		0x40, 0x06, 0xb5, 0x94, // TTL, Protocol, Header Checksum
		0x0a, 0x00, 0x00, 0x01, // Source IP (10.0.0.2)
		0x0a, 0x00, 0x00, 0x02, // Destination IP (10.0.0.1)
		// UDP header = 8 bytes
		0x75, 0x30, 0x75, 0x30, // Source Port (30000), Destination Port (30000), TODO: Subject to change
		0x00, 0x9, 0x6b, 0xeb, // Length, Checksum
		// Payload
		0xFF, // Data
	}

	// From https://css.bz/2016/12/08/go-raw-sockets.html
	// Socket is defined as:
	// func Socket(domain, typ, proto int) (fd int, err error)
	// Domain specifies the protocol family to be used - this should be AF_PACKET
	// to indicate we want the low level packet interface
	// Type specifies the semantics of the socket
	// Protocol specifies the protocol to use - kept here as ETH_P_ALL to
	// indicate all protocols over Ethernet
	/*
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW,
			syscall.ETH_P_ALL) // ETH_P_ALL works for Linux/Unix so may show as undefined on Windows
		if err != nil {
			fmt.Println("Error1: " + err.Error())
			return
		}
		fmt.Println("Obtained fd ", fd)
	*/

	// From https://stackoverflow.com/questions/35841275/sending-raw-packet-with-ethernet-header-using-go-language
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		fmt.Println("Error1: " + err.Error())
	}

	if_info, err := net.InterfaceByName("enp7s0")
	if err != nil {
		fmt.Println("Error2: " + err.Error())
	}

	var haddr [8]byte
	copy(haddr[0:7], if_info.HardwareAddr[0:7])
	fmt.Println(haddr)
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

	err = syscall.SetLsfPromisc("enp7s0", true) // TODO: What does this do?
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

	err = syscall.SetLsfPromisc("enp7s0", false)
	if err != nil {
		fmt.Println("Error6: " + err.Error())
	}

	syscall.Close(fd)
	/*
		if_info, err := net.InterfaceByName("Local Area Connection* 1")
		if err != nil {
			fmt.Println("Error2: " + err.Error())
			return
		}

		var haddr [8]byte
		fmt.Println((if_info.HardwareAddr))
		fmt.Println((if_info.HardwareAddr[0:6]))
		copy(haddr[0:7], if_info.HardwareAddr[0:6])
	*/
}
