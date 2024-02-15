package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	// Get the public IPs of the nodes with count of number of pods running on each node
	// Create a string bash command
	kube_cmd_ips := "for NODE in $(kubectl get pods -o jsonpath=\"{..nodeName}\" " +
		"| tr -s '[[:space:]]' '\\n' | sort | awk '{print $2\"\\t\"$1}'); " +
		"do kubectl describe nodes | grep 'Name:\\|public-ip' " +
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
		"go-template='{{range .items}}{{range.spec.ports}}{{if .nodePort}}{{.nodePort}}{{\"\"}}{{end}}{{end}}{{end}}'"
	get_port_command := exec.Command("bash", "-c", kube_cmd_port)
	stdout, err = get_port_command.Output()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	port, err_port := strconv.ParseInt(string(stdout), 10, 64) // <- Convert string (in bytes) to int64
	if err_port != nil {
		panic(err_port)
	}
	// Convert integer port to bytes
	fmt.Println("Port number:", port)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, port)
	port_bytes := buf.Bytes()[len(buf.Bytes())-2 : len(buf.Bytes())] // Get the last 2 bytes
	// Create array of strings of IP addresses
	fmt.Println("IPs:\n" + string(ips))
	ips_string_arr := strings.Split(string(ips), "\n")
	// Convert length of IP address to bytes
	buf = new(bytes.Buffer)
	num_replicas := int64(len(ips_string_arr) - 1) // Minus 1 for an extra newline
	fmt.Println("Number of Replicas:", num_replicas)
	err_write := binary.Write(buf, binary.BigEndian, num_replicas)
	if err_write != nil {
		panic(err_write)
	}
	num_replicas_bytes := buf.Bytes()[len(buf.Bytes())-2 : len(buf.Bytes())] // Get the last 2 bytes

	// Create payload
	payload := []byte{}
	payload = append(payload, port_bytes...)
	payload = append(payload, num_replicas_bytes...)
	for i := 0; i < len(ips_string_arr)-1; i++ {
		bytes_ip := []byte{4}
		bytes_ip = net.ParseIP(ips_string_arr[i])[12:16]
		payload = append(payload, bytes_ip...)
	}
	//establish connection
	connection, err := net.Dial("udp", "10.0.0.1:7777")
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
}
