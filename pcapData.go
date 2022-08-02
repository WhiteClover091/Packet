package main

import (
	"bufio"
	"encoding/binary"
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
	packet.reader = *bufio.NewReaderSize(file, 1<<12)
	pcap_hdr_s := make([]byte, GlobalHeaderLength)
	packet.reader.Read(pcap_hdr_s)
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
	_, err := p.reader.Read(pcaprec_hdr_s)
	if err != nil {
		return nil, err
	}
	packet.ts_sec = uint32(pcaprec_hdr_s[3])<<24 + uint32(pcaprec_hdr_s[2])<<16 + uint32(pcaprec_hdr_s[1])<<8 + uint32(pcaprec_hdr_s[0])
	packet.ts_usec = uint32(pcaprec_hdr_s[7])<<24 + uint32(pcaprec_hdr_s[6])<<16 + uint32(pcaprec_hdr_s[5])<<8 + uint32(pcaprec_hdr_s[4])
	packet.orig_len = uint32(pcaprec_hdr_s[11])<<24 + uint32(pcaprec_hdr_s[10])<<16 + uint32(pcaprec_hdr_s[9])<<8 + uint32(pcaprec_hdr_s[8])
	packet.incl_len = uint32(pcaprec_hdr_s[15])<<24 + uint32(pcaprec_hdr_s[14])<<16 + uint32(pcaprec_hdr_s[13])<<8 + uint32(pcaprec_hdr_s[12])
	packetData := make([]byte, packet.incl_len)
	_, err = p.reader.Read(packetData)
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
