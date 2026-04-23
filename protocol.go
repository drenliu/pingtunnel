package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	MagicRequest  uint32 = 0x50545251
	MagicResponse uint32 = 0x50545250

	CmdSetup             uint8 = 1
	CmdSetupAck          uint8 = 2
	CmdConnect           uint8 = 3
	CmdConnectAck        uint8 = 4
	CmdData              uint8 = 5
	CmdClose             uint8 = 6
	CmdPing              uint8 = 7
	CmdDataAck           uint8 = 8
	CmdSocksDial         uint8 = 9  // client -> server: dynamic forward dial host:port in Data
	CmdSocksDialAck      uint8 = 10 // server -> client: dial succeeded
	CmdSocksRegister     uint8 = 11 // client -> server: register SOCKS-only tunnel (no -l/-t)
	CmdSocksRegisterNack uint8 = 12 // server -> client: SOCKS dynamic disabled on server

	FlagMore uint8 = 0x01

	MaxPayloadSize = 1300

	// Magic(4) + KeyHash(16) + Cmd(1) + Flags(1) + ConnID(4) + Seq(4) + DataLen(2)
	HeaderSize   = 32
	ProtocolICMP = 1
)

type TunnelPacket struct {
	Magic   uint32
	KeyHash [16]byte
	Cmd     uint8
	Flags   uint8
	ConnID  uint32
	Seq     uint32
	Data    []byte
}

func ComputeKeyHash(key string) [16]byte {
	return md5.Sum([]byte(key))
}

func (p *TunnelPacket) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Grow(HeaderSize + len(p.Data))

	binary.Write(buf, binary.BigEndian, p.Magic)
	buf.Write(p.KeyHash[:])
	buf.WriteByte(p.Cmd)
	buf.WriteByte(p.Flags)
	binary.Write(buf, binary.BigEndian, p.ConnID)
	binary.Write(buf, binary.BigEndian, p.Seq)
	binary.Write(buf, binary.BigEndian, uint16(len(p.Data)))
	if len(p.Data) > 0 {
		buf.Write(p.Data)
	}
	return buf.Bytes(), nil
}

func DecodeTunnelPacket(data []byte) (*TunnelPacket, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("packet too short: %d < %d", len(data), HeaderSize)
	}

	p := &TunnelPacket{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.BigEndian, &p.Magic)
	if p.Magic != MagicRequest && p.Magic != MagicResponse {
		return nil, errors.New("invalid magic")
	}

	r.Read(p.KeyHash[:])
	p.Cmd, _ = r.ReadByte()
	p.Flags, _ = r.ReadByte()
	binary.Read(r, binary.BigEndian, &p.ConnID)
	binary.Read(r, binary.BigEndian, &p.Seq)

	var dataLen uint16
	binary.Read(r, binary.BigEndian, &dataLen)

	if dataLen > 0 {
		p.Data = make([]byte, dataLen)
		n, _ := r.Read(p.Data)
		if n != int(dataLen) {
			return nil, fmt.Errorf("short data: got %d, want %d", n, dataLen)
		}
	}
	return p, nil
}
