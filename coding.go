package main

import (
	"encoding/binary"
	"errors"
)

func decodeUint8(msg []byte, off int) (uint8, int, error) {
	if (off + 1) > len(msg) {
		return 0, len(msg), errors.New("Overflow in decoding uint8")
	}
	return msg[off], off + 1, nil
}

func encodeUint8(val uint8, msg []byte, off int) (int, error) {
	if (off + 1) > len(msg) {
		return len(msg), errors.New("Overflow in encoding uint8")
	}
	msg[off] = val
	return off + 1, nil
}

func decodeUint16(msg []byte, off int) (uint16, int, error) {
	if (off + 2) > len(msg) {
		return 0, len(msg), errors.New("Overflow in decoding uint16")
	}
	return binary.BigEndian.Uint16(msg[off:]), off + 2, nil
}

func encodeUint16(val uint16, msg []byte, off int) (int, error) {
	if (off + 2) > len(msg) {
		return len(msg), errors.New("Overflow in encoding uint8")
	}
	binary.BigEndian.PutUint16(msg[off:], val)
	return off + 2, nil
}

func decodeUint32(msg []byte, off int) (uint32, int, error) {
	if (off + 4) > len(msg) {
		return 0, len(msg), errors.New("Overflow in decoding uint32")
	}
	return binary.BigEndian.Uint32(msg[off:]), off + 4, nil
}

func encodeUint32(val uint32, msg []byte, off int) (int, error) {
	if (off + 4) > len(msg) {
		return len(msg), errors.New("Overflow in encoding uint8")
	}
	binary.BigEndian.PutUint32(msg[off:], val)
	return off + 4, nil
}

func decodeUint64(msg []byte, off int) (uint64, int, error) {
	if (off + 8) > len(msg) {
		return 0, len(msg), errors.New("Overflow in decoding uint64")
	}
	return binary.BigEndian.Uint64(msg[off:]), off + 8, nil
}

func encodeUint64(val uint64, msg []byte, off int) (int, error) {
	if (off + 8) > len(msg) {
		return len(msg), errors.New("Overflow in encoding uint8")
	}
	binary.BigEndian.PutUint64(msg[off:], val)
	return off + 8, nil
}
