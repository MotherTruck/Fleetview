package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSendWakeOnLANBroadcastsARealCorrectMagicPacket(t *testing.T) {
	// Bind a real UDP listener on the WoL port and confirm the exact 102-byte
	// magic packet arrives: 6 bytes of 0xFF followed by the target MAC
	// repeated 16 times.
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 9})
	if err != nil {
		t.Skipf("could not bind UDP port 9 in this environment (needs elevated privileges below 1024): %v", err)
	}
	defer listener.Close()
	_ = listener.SetReadDeadline(time.Now().Add(3 * time.Second))

	received := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 256)
		n, _, err := listener.ReadFromUDP(buffer)
		if err != nil {
			received <- nil
			return
		}
		received <- append([]byte(nil), buffer[:n]...)
	}()

	if err := sendWakeOnLAN("aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("sendWakeOnLAN failed: %v", err)
	}

	packet := <-received
	if packet == nil {
		t.Fatal("did not receive a broadcast packet")
	}
	if len(packet) != 102 {
		t.Fatalf("expected a 102-byte magic packet, got %d bytes", len(packet))
	}
	if !bytes.Equal(packet[:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Errorf("expected the first 6 bytes to be 0xFF sync stream, got %x", packet[:6])
	}
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := 0; i < 16; i++ {
		chunk := packet[6+i*6 : 12+i*6]
		if !bytes.Equal(chunk, mac) {
			t.Errorf("MAC repetition %d = %x, want %x", i, chunk, mac)
		}
	}
}

func TestSendWakeOnLANRejectsInvalidMAC(t *testing.T) {
	err := sendWakeOnLAN("not-a-real-mac-address")
	if err == nil {
		t.Fatal("expected an error for an invalid MAC address")
	}
	if !strings.Contains(err.Error(), "invalid MAC") {
		t.Errorf("expected a clear invalid-MAC error, got: %v", err)
	}
}
