package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// sendWakeOnLAN broadcasts a standard Wake-on-LAN magic packet (6 bytes of
// 0xFF followed by the target MAC repeated 16 times) on the local subnet.
// This has to run on a device that's actually on the same LAN as the
// sleeping target -- broadcast packets don't cross routers -- which is
// exactly what the server-side dispatch enforces: a WAKE_ON_LAN job is
// only ever handed to a device that's currently online, never the
// (necessarily asleep) target itself.
func sendWakeOnLAN(mac string) error {
	hwAddr, err := parseMACAddress(mac)
	if err != nil {
		return err
	}
	packet := make([]byte, 0, 6+16*len(hwAddr))
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xFF)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, hwAddr...)
	}

	broadcastAddr, err := net.ResolveUDPAddr("udp4", "255.255.255.255:9")
	if err != nil {
		return fmt.Errorf("resolve broadcast address: %w", err)
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return fmt.Errorf("open UDP socket: %w", err)
	}
	defer conn.Close()
	// A UDP socket cannot send to a broadcast address until SO_BROADCAST is
	// set explicitly (platform-specific: see wol_linux.go/wol_windows.go);
	// without it this fails with a permission error at the OS level.
	if err := enableBroadcast(conn); err != nil {
		return fmt.Errorf("enable broadcast: %w", err)
	}
	_, err = conn.WriteToUDP(packet, broadcastAddr)
	return err
}

func parseMACAddress(mac string) ([]byte, error) {
	cleaned := strings.NewReplacer("-", "", ":", "", ".", "").Replace(mac)
	if len(cleaned) != 12 {
		return nil, fmt.Errorf("invalid MAC address %q", mac)
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %q: %w", mac, err)
	}
	return decoded, nil
}
