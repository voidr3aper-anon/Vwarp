package masque

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Capsule types as defined in RFC 9297
const (
	CapsuleTypeDatagram       = 0x00
	CapsuleTypeAddressAssign  = 0x01
	CapsuleTypeAddressRequest = 0x02
	CapsuleTypeRouteAdvertise = 0x03
)

// Capsule represents a MASQUE capsule
type Capsule struct {
	Type   uint64
	Length uint64
	Value  []byte
}

// WriteCapsule writes a capsule to the writer
func WriteCapsule(w io.Writer, capsuleType uint64, value []byte) error {
	// Write capsule type (varint)
	if err := writeVarint(w, capsuleType); err != nil {
		return fmt.Errorf("failed to write capsule type: %w", err)
	}

	// Write capsule length (varint)
	if err := writeVarint(w, uint64(len(value))); err != nil {
		return fmt.Errorf("failed to write capsule length: %w", err)
	}

	// Write capsule value
	if _, err := w.Write(value); err != nil {
		return fmt.Errorf("failed to write capsule value: %w", err)
	}

	return nil
}

// ReadCapsule reads a capsule from the reader
func ReadCapsule(r io.Reader) (*Capsule, error) {
	// Read capsule type (varint)
	capsuleType, err := readVarint(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read capsule type: %w", err)
	}

	// Read capsule length (varint)
	length, err := readVarint(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read capsule length: %w", err)
	}

	// Read capsule value
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fmt.Errorf("failed to read capsule value: %w", err)
	}

	return &Capsule{
		Type:   capsuleType,
		Length: length,
		Value:  value,
	}, nil
}

// writeVarint writes a variable-length integer (QUIC varint encoding)
func writeVarint(w io.Writer, v uint64) error {
	var buf [8]byte
	var length int

	switch {
	case v < 64:
		// 1-byte encoding: 00xxxxxx
		buf[0] = byte(v)
		length = 1
	case v < 16384:
		// 2-byte encoding: 01xxxxxx xxxxxxxx
		binary.BigEndian.PutUint16(buf[:2], uint16(v)|0x4000)
		length = 2
	case v < 1073741824:
		// 4-byte encoding: 10xxxxxx ...
		binary.BigEndian.PutUint32(buf[:4], uint32(v)|0x80000000)
		length = 4
	default:
		// 8-byte encoding: 11xxxxxx ...
		binary.BigEndian.PutUint64(buf[:8], v|0xC000000000000000)
		length = 8
	}

	_, err := w.Write(buf[:length])
	return err
}

// readVarint reads a variable-length integer (QUIC varint encoding)
func readVarint(r io.Reader) (uint64, error) {
	var firstByte [1]byte
	if _, err := io.ReadFull(r, firstByte[:]); err != nil {
		return 0, err
	}

	// Extract the length from the first two bits
	prefix := firstByte[0] >> 6

	var value uint64
	var buf [7]byte

	switch prefix {
	case 0: // 1-byte encoding
		value = uint64(firstByte[0] & 0x3F)
	case 1: // 2-byte encoding
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return 0, err
		}
		value = uint64(firstByte[0]&0x3F)<<8 | uint64(buf[0])
	case 2: // 4-byte encoding
		if _, err := io.ReadFull(r, buf[:3]); err != nil {
			return 0, err
		}
		value = uint64(firstByte[0]&0x3F)<<24 | uint64(buf[0])<<16 | uint64(buf[1])<<8 | uint64(buf[2])
	case 3: // 8-byte encoding
		if _, err := io.ReadFull(r, buf[:7]); err != nil {
			return 0, err
		}
		value = uint64(firstByte[0]&0x3F)<<56 |
			uint64(buf[0])<<48 | uint64(buf[1])<<40 | uint64(buf[2])<<32 | uint64(buf[3])<<24 |
			uint64(buf[4])<<16 | uint64(buf[5])<<8 | uint64(buf[6])
	}

	return value, nil
}
