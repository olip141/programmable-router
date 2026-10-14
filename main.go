package main

/*
#cgo pkg-config: libndpi
#include <ndpi_api.h>
*/
import "C"

import (
	"fmt"
	"os"

	"github.com/google/gopacket/pcap"
)

func main() {
	revision := C.GoString(C.ndpi_revision())
	apiVersion := uint16(C.ndpi_get_api_version())

	fmt.Printf("nDPI revision: %s\n", revision)
	fmt.Printf("nDPI API version: %d\n", apiVersion)

	devs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap.FindAllDevs: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("pcap devices:")
	for _, dev := range devs {
		fmt.Printf("  %s\n", dev.Name)
	}
}
