package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"os"
	"time"
)

const (
	GlobalHeaderLength = 24
	PacketHeaderLength = 16
)

type pcap_hdr_s struct {
	magic_number  uint32
	version_major uint16
	version_minor uint16
	thiszone      uint32 //always zero
	sigfigs       uint32 //always zero
	snaplen       uint32
	network       uint32
}
type PacketSource struct {
	reader bufio.Reader
	endian binary.ByteOrder
	pcap_hdr_s
}

func ReadPcapData(filename string) *PacketSource {
	var packet PacketSource
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	packet.reader = *bufio.NewReader(file)
	pcap_hdr_s := make([]byte, GlobalHeaderLength)
	_, err = io.ReadFull(&packet.reader, pcap_hdr_s)
	if err != nil {
		log.Fatal(err)
	}
	packet.magic_number = binary.BigEndian.Uint32(pcap_hdr_s)
	if packet.magic_number == 0xd4c3b2a1 {
		packet.endian = binary.LittleEndian
	} else if packet.magic_number == 0xa1b2c3d4 {
		packet.endian = binary.BigEndian
	} else {
		log.Fatal("This file may not be a pcapfile, magic number should be 0xd4c3b2a1 or 0xa1b2c3d4\n")
	}
	packet.version_major = packet.endian.Uint16(pcap_hdr_s[4:])
	packet.version_minor = packet.endian.Uint16(pcap_hdr_s[6:])
	packet.thiszone = packet.endian.Uint32(pcap_hdr_s[8:])
	packet.sigfigs = packet.endian.Uint32(pcap_hdr_s[12:])
	packet.snaplen = packet.endian.Uint32(pcap_hdr_s[16:])
	packet.network = packet.endian.Uint32(pcap_hdr_s[20:])
	return &packet
}

type pcaprec_hdr_s struct {
	ts_sec   uint32
	ts_usec  uint32
	incl_len uint32
	orig_len uint32
}
type Packet struct {
	pcaprec_hdr_s
	packetData []byte
	endian     binary.ByteOrder
}

func (p *PacketSource) NextPacket() (*Packet, error) {
	var packet Packet
	pcaprec_hdr_s := make([]byte, PacketHeaderLength)
	_, err := io.ReadFull(&p.reader, pcaprec_hdr_s)
	if err != nil {
		return nil, err
	}
	packet.ts_sec = p.endian.Uint32(pcaprec_hdr_s)
	packet.ts_usec = p.endian.Uint32(pcaprec_hdr_s[4:])
	packet.incl_len = p.endian.Uint32(pcaprec_hdr_s[8:])
	packet.orig_len = p.endian.Uint32(pcaprec_hdr_s[12:])
	packetData := make([]byte, packet.incl_len)
	_, err = io.ReadFull(&p.reader, packetData)
	if err != nil {
		return nil, err
	}
	packet.packetData = packetData
	packet.endian = p.endian
	return &packet, nil
}

func (p *Packet) CaptureTime() time.Time {
	return time.Unix(int64(p.ts_sec), int64(p.ts_usec)*1000)
}
