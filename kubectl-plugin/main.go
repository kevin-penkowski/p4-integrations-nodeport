package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func main() {
	// ----------------- Week 4 -----------------

	// Get the public IPs of the nodes with count of number of pods running on each node
	// Create a string bash command
	kube_cmd_ips := "for NODE in $(kubectl get pods -o jsonpath=\"{..nodeName}\" " +
		"| tr -s '[[:space:]]' '\\n' | sort | awk '{print $2\"\\t\"$1}'); " +
		"do kubectl describe nodes | grep 'Name:\\|flannel.alpha.coreos.com/public-ip' " +
		"| awk '{print $2}' | paste - - | grep $NODE | awk '{print $2}'; done | tr -s '[[:space:]]' '\n'"
	// Execute the bash command
	get_ips_command := exec.Command("bash", "-c", kube_cmd_ips)
	stdout, err := get_ips_command.Output()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	ips := stdout
	// Get the NodePort port number of the service
	kube_cmd_port := "kubectl get svc --all-namespaces -o " +
		"go-template='{{range .items}}{{range.spec.ports}}{{if .nodePort}}{{.nodePort}}{{\"\\n\"}}{{end}}{{end}}{{end}}'"
	get_port_command := exec.Command("bash", "-c", kube_cmd_port)
	stdout, err = get_port_command.Output()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	port := stdout // <- Is a byte array of the string of the port number
	fmt.Println(port)
	fmt.Println(string(port))
	// Get command output as byte array
	fmt.Println(string(ips))
	ips_string_arr := strings.Split(string(ips), "\n")
	payload := []byte{}
	payload = append(payload, port...)
	for i := 0; i < len(ips_string_arr); i++ {
		payload = append(payload, net.ParseIP(ips_string_arr[i])...)
	}
	//establish connection
	connection, err := net.Dial("udp", "10.0.0.1:30000")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// send IPs packet
	_, err = connection.Write(payload)
	if err != nil {
		fmt.Println("Error sending:", err.Error())
		return
	}
	fmt.Println("Sent: ", payload)
	defer connection.Close()

	/*
		// Receive packets
		buffer := make([]byte, 1024)
		mLen, err := connection.Read(buffer)
			if err != nil {
				fmt.Println("Error reading:", err.Error())
			}
			fmt.Println("Received: ", string(buffer[:mLen]))
			defer connection.Close()
	*/
	/*
		// Raw packet construction
		// Construct a packet to send
		pkt := []byte{
			// Ethernet header = 14 bytes
			0x12, 0x65, 0x6b, 0x54, 0xCB, 0x90, // Destination MAC (12:65:6B:54:CB:90)
			0x16, 0x9b, 0x47, 0x4e, 0x47, 0x4c, // Source MAC (16:9B:47:4E:47:4C)
			0x08, 0x00, // Type = IP
			// IP header = 20 bytes
			0x45, 0x00, 0x00, 0x3c, // Version, IHL, TOS, Length TODO: Edit length
			0x47, 0xd9, 0x40, 0x00, // ID, Flags, Fragment Offset
			0x40, 0x06, 0xb5, 0x94, // TTL, Protocol, Header Checksum
			0x0a, 0x00, 0x00, 0x01, // Source IP (10.0.0.2)
			0x0a, 0x00, 0x00, 0x02, // Destination IP (10.0.0.1)
			// UDP header = 8 bytes
			0x75, 0x30, 0x75, 0x30, // Source Port (30000), Destination Port (30000), TODO: Subject to change
			0x00, byte(len(ips)), 0x6b, 0xeb, // Length, Checksum
			// Total length = 42 + length of ips bytes
		}
		// Append the public IPs to the packet as the payload
		pkt = append(pkt, ips...)
	*/

	// ----------------- Week 3 -----------------
	/*
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
	*/
}
