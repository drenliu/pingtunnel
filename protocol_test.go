package main

import (
	"bytes"
	"testing"
)

func TestComputeKeyHashDeterministic(t *testing.T) {
	a := ComputeKeyHash("mykey")
	b := ComputeKeyHash("mykey")
	if a != b {
		t.Fatal("same key should yield same hash")
	}
	if bytes.Equal(a[:], make([]byte, 16)) {
		t.Fatal("hash should not be all zeros")
	}
}

func TestTunnelPacketEncodeDecodeRoundtrip(t *testing.T) {
	key := ComputeKeyHash("k")
	p := &TunnelPacket{
		Magic:   MagicRequest,
		KeyHash: key,
		Cmd:     CmdData,
		Flags:   FlagMore,
		ConnID:  0x4030201,
		Seq:     99,
		Data:    []byte("hello tunnel"),
	}
	raw, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < HeaderSize {
		t.Fatalf("encoded len %d < HeaderSize %d", len(raw), HeaderSize)
	}
	got, err := DecodeTunnelPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Magic != p.Magic || got.Cmd != p.Cmd || got.Flags != p.Flags || got.ConnID != p.ConnID || got.Seq != p.Seq {
		t.Fatalf("header mismatch: %+v vs %+v", got, p)
	}
	if !bytes.Equal(got.Data, p.Data) {
		t.Fatalf("data %q want %q", got.Data, p.Data)
	}
}

func TestTunnelPacketEncodeEmptyData(t *testing.T) {
	p := &TunnelPacket{Magic: MagicResponse, Cmd: CmdPing}
	raw, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTunnelPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 0 {
		t.Fatalf("want empty Data, got %d bytes", len(got.Data))
	}
}

func TestDecodeTunnelPacketTooShort(t *testing.T) {
	_, err := DecodeTunnelPacket(make([]byte, HeaderSize-1))
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}

func TestDecodeTunnelPacketInvalidMagic(t *testing.T) {
	buf := make([]byte, HeaderSize+4)
	// garbage magic
	buf[0], buf[1], buf[2], buf[3] = 0, 0, 0, 0
	_, err := DecodeTunnelPacket(buf)
	if err == nil {
		t.Fatal("expected invalid magic error")
	}
}

func TestDecodeTunnelPacketShortDataField(t *testing.T) {
	buf := new(bytes.Buffer)
	// MagicRequest + key + cmd + flags + conn + seq + dataLen=5 but only 2 data bytes
	writeU32BE(buf, MagicRequest)
	buf.Write(make([]byte, 16))
	buf.WriteByte(CmdPing)
	buf.WriteByte(0)
	writeU32BE(buf, 1)
	writeU32BE(buf, 1)
	writeU16BE(buf, 5)
	buf.WriteByte(1)
	buf.WriteByte(2)
	_, err := DecodeTunnelPacket(buf.Bytes())
	if err == nil {
		t.Fatal("expected short data error")
	}
}

func writeU32BE(b *bytes.Buffer, v uint32) {
	_ = b.WriteByte(byte(v >> 24))
	_ = b.WriteByte(byte(v >> 16))
	_ = b.WriteByte(byte(v >> 8))
	_ = b.WriteByte(byte(v))
}

func writeU16BE(b *bytes.Buffer, v uint16) {
	_ = b.WriteByte(byte(v >> 8))
	_ = b.WriteByte(byte(v))
}
