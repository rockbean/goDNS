package main

import (
	"errors"
	"fmt"
	"strings"
)

// DNS header
type dnsHeader struct {
	id      uint16
	flags   uint16
	qdCount uint16
	anCount uint16
	nsCount uint16
	arCount uint16
}

// DNS question
type dnsQuestion struct {
	qName  string
	qType  uint16
	qClass uint16
}

type dnsTxtRecord struct {
	txtLen  uint8
	txtData string
}

type dnsARecord struct {
	addr [4]uint8
}

type dnsSOARecord struct {
	mName   string
	nName   string
	serial  uint32
	refresh uint32
	retry   uint32
	expire  uint32
	minimum uint32
}

/* Name String Record
 * 1. name server
 * 2. cname
 * 3. ptr
 */
type dnsNameRecord struct {
	name string
}

type dnsMxRecord struct {
	preference uint16
	exchange   string
}

type dnsAAAARecord struct {
	addr [16]uint8
}

type dnsSrvRecord struct {
	priority uint16
	weight   uint16
	port     uint16
	target   string
}

// DNS Record
type dnsRecord struct {
	rdName   string
	rdType   uint16
	rdClass  uint16
	rdTTL    uint32
	rdLength uint16
	rdData   []byte
}

// DNS data struct
type dnsMsg struct {
	id uint16 // Identifier
	// Flags
	qr     bool   // Query/Response Flag
	opcode uint16 // Operation Code
	aa     bool   // Authoritative Answer Flag
	tc     bool   // Truncation Flag
	rd     bool   // Recursion Desired
	ra     bool   // Recursion Available
	rcode  uint16 // Response Code
	// Counts
	qdCount uint16 // Question Count
	anCount uint16 // Answer Record Count
	nsCount uint16 // Authority Record Count
	arCount uint16 // Additional Record Count

	questions   []dnsQuestion
	answers     []dnsRecord
	authorities []dnsRecord
	additionals []dnsRecord
}

// DNS flags
const (
	QR_MASK     = 1 << 15 // query/response (response=1)
	OPCODE_MASK = 1 << 11 // Operation Code
	AA_MASK     = 1 << 10 // authoritative
	TC_MASK     = 1 << 9  // truncated
	RD_MASK     = 1 << 8  // recursion desired
	RA_MASK     = 1 << 7  // recursion available
	RCODE_MASK  = 0xf     // Response Code
)

// DNS Response Type
const (
	RESP_OK = iota
	RESP_FORMAT_ERROR
	RESP_SERVER_FAILURE
	RESP_NAME_ERROR
	RESP_NOT_IMPLEMENTED
	RESP_REFUSED
)

// DNS Resource Record Type
const (
	RESOURCE_RECORD_A     = 1
	RESOURCE_RECORD_NS    = 2
	RESOURCE_RECORD_CNAME = 5
	RESOURCE_RECORD_SOA   = 6
	RESOURCE_RECORD_PTR   = 12
	RESOURCE_RECORD_MX    = 15
	RESOURCE_RECORD_TXT   = 16
	RESOURCE_RECORD_AAAA  = 28
	RESOURCE_RECORD_SRV   = 33
)

func decodeDnsHdr(buff []byte, off int) (dnsHeader, int, error) {
	var (
		hdr dnsHeader
		err error
	)

	hdr.id, off, err = decodeUint16(buff, off)
	if err != nil {
		return hdr, off, err
	}

	hdr.flags, off, err = decodeUint16(buff, off)
	if err != nil {
		return hdr, off, err
	}

	hdr.qdCount, off, err = decodeUint16(buff, off)
	if err != nil {
		return hdr, off, err
	}

	hdr.anCount, off, err = decodeUint16(buff, off)
	if err != nil {
		return hdr, off, err
	}

	hdr.nsCount, off, err = decodeUint16(buff, off)
	if err != nil {
		return hdr, off, err
	}

	hdr.arCount, off, err = decodeUint16(buff, off)
	if err != nil {
		return hdr, off, err
	}

	return hdr, off, nil
}

func decodeDomainName(buff []byte, off int) (string, int, error) {
	size := len(buff)
	domain := make([]byte, 0, 1024)

	for {
		if off >= size {
			return "", size, errors.New("Data is too small")
		}
		len := int(buff[off])
		off++
		if (len & 0xC0) == 0 {
			if len == 0 {
				break
			}

			if off+len > size {
				return "", size, errors.New("Data is too small")
			}

			for _, c := range buff[off : off+len] {
				domain = append(domain, c)
			}
			domain = append(domain, '.')
			off += len
		} else if (len & 0xC0) == 0xC0 {
			//Todo: Parse compression domain
		} else {
			return "", size, errors.New("Data is unknown")
		}
	}

	if len(domain) == 0 {
		return ".", off, nil
	}

	return string(domain), off, nil
}

func decodeQuestion(buff []byte, off int) (dnsQuestion, int, error) {
	var (
		question dnsQuestion
		err      error
	)
	question.qName, off, err = decodeDomainName(buff, off)
	if err != nil {
		return question, off, err
	}
	if off == len(buff) {
		return question, off, nil
	}
	question.qType, off, err = decodeUint16(buff, off)
	if err != nil {
		return question, off, err
	}
	if off == len(buff) {
		return question, off, nil
	}

	question.qClass, off, err = decodeUint16(buff, off)
	if off == len(buff) {
		return question, off, nil
	}
	return question, off, err
}

func (dns *dnsMsg) decodeBody(hdr dnsHeader, buff []byte, off int) (err error) {
	// no more data in body
	if off == len(buff) {
		dns.questions = nil
		dns.answers = nil
		dns.authorities = nil
		dns.additionals = nil
		return nil
	}

	// Parse questions
	var q dnsQuestion
	dns.questions = nil
	for i := 0; i < int(hdr.qdCount); i++ {
		_off := off
		q, off, err = decodeQuestion(buff, off)
		if err != nil {
			return err
		}
		// In case of wrong qdCount from recv msg
		if _off == off {
			dns.qdCount = uint16(i)
			break
		}
		fmt.Println(i, "QUERY ", q.qName, q.qType, q.qClass)
		dns.questions = append(dns.questions, q)
	}
	dns.qdCount = uint16(len(dns.questions))

	return err
}

func (dns *dnsMsg) parseDnsHdr(hdr dnsHeader) {
	dns.id = hdr.id
	dns.qr = (hdr.flags & QR_MASK) != 0
	dns.opcode = uint16(hdr.flags&OPCODE_MASK) & 0xff
	dns.aa = (hdr.flags & AA_MASK) != 0
	dns.tc = (hdr.flags & TC_MASK) != 0
	dns.rd = (hdr.flags & RD_MASK) != 0
	dns.ra = (hdr.flags & RA_MASK) != 0
	dns.rcode = uint16(hdr.flags&RCODE_MASK) & 0xff
}

func (dns *dnsMsg) decodeMsg(buffer []byte) (err error) {
	fmt.Println("Decode DNS msg.....")
	// decode header
	hdr, off, err := decodeDnsHdr(buffer, 0)
	if err != nil {
		return err
	}

	if off == 0 {
		fmt.Println("Fail to decode DNS header")
	}

	dns.parseDnsHdr(hdr)

	err = dns.decodeBody(hdr, buffer, off)
	return err
}

func (rd *dnsRecord) queryARecord(domain string) error {
	if strings.Compare(domain, "www.baidu.com.") == 0 {
		rd.rdLength = 4
		rd.rdData = make([]byte, 4)
		rd.rdData[0] = 10
		rd.rdData[1] = 10
		rd.rdData[2] = 0
		rd.rdData[3] = 1
	} else {
		return errors.New("Unknown domain: " + domain)
	}
	return nil
}

func (rd *dnsRecord) queryAAAARecord(domain string) error {
	if strings.Compare(domain, "www.baidu.com.") == 0 {
		rd.rdLength = 16
		rd.rdData = make([]byte, 16)
		rd.rdData[0] = 0xfe
		rd.rdData[1] = 0x80
		rd.rdData[2] = 0
		rd.rdData[3] = 0
		rd.rdData[4] = 0
		rd.rdData[5] = 0
		rd.rdData[6] = 0
		rd.rdData[7] = 0
		rd.rdData[8] = 0
		rd.rdData[9] = 0
		rd.rdData[10] = 0
		rd.rdData[11] = 0
		rd.rdData[12] = 0
		rd.rdData[13] = 0
		rd.rdData[14] = 0
		rd.rdData[15] = 1
	} else {
		return errors.New("Unknown domain: " + domain)
	}
	return nil
}

func (rd *dnsRecord) queryTXTRecord(domain string) error {
	if strings.Compare(domain, "www.baidu.com.") == 0 {
		str := "Hello World"
		rd.rdData = []byte(str)
	} else {
		return errors.New("Unknown domain: " + domain)
	}
	return nil
}

func (dns *dnsMsg) resolveMsg() (err error) {
	fmt.Println("Resolve DNS msg....")
	// Fake response
	dns.qr = true
	dns.aa = true
	dns.ra = false
	dns.rcode = RESP_OK

	dns.anCount = 0
	dns.nsCount = 0
	dns.arCount = 0

	// Fake answer records
	var record dnsRecord
	dns.answers = nil
	for _, question := range dns.questions {
		record.rdName = question.qName
		record.rdType = question.qType
		record.rdClass = question.qClass
		record.rdTTL = 60 * 60

		switch record.rdType {
		case RESOURCE_RECORD_A:
			err = record.queryARecord(record.rdName)
		case RESOURCE_RECORD_AAAA:
			err = record.queryAAAARecord(record.rdName)
		case RESOURCE_RECORD_TXT:
			err = record.queryTXTRecord(record.rdName)
		default:
			dns.rcode = RESP_NOT_IMPLEMENTED
			fmt.Println("Can't answer question of type ", record.rdType)
			continue
		}
		if err != nil {
			return err
		}

		dns.answers = append(dns.answers, record)
		dns.anCount++
	}

	return nil
}

func (dns *dnsMsg) encodeDnsHdr(buff []byte, off int) (int, error) {
	off, err := encodeUint16(dns.id, buff, off)
	if err != nil {
		return off, err
	}

	var flags uint16
	flags = uint16(dns.rcode&RCODE_MASK) | uint16(dns.opcode<<11)
	if dns.qr {
		flags |= QR_MASK
	}
	if dns.aa {
		flags |= AA_MASK
	}
	if dns.tc {
		flags |= TC_MASK
	}
	if dns.rd {
		flags |= RD_MASK
	}
	if dns.ra {
		flags |= RA_MASK
	}

	off, err = encodeUint16(flags, buff, off)
	if err != nil {
		return off, err
	}

	off, err = encodeUint16(dns.qdCount, buff, off)
	if err != nil {
		return off, err
	}

	off, err = encodeUint16(dns.anCount, buff, off)
	if err != nil {
		return off, err
	}

	off, err = encodeUint16(dns.nsCount, buff, off)
	if err != nil {
		return off, err
	}

	off, err = encodeUint16(dns.arCount, buff, off)
	if err != nil {
		return off, err
	}

	return off, nil
}

func encodeDomainName(s string, buff []byte, off int) (int, error) {
	size := len(s)
	isDot := false
	ptr := 0
	// No Valid query domain
	if size == 0 {
		return off, nil
	}
	for i := 0; i < size; i++ {
		var c byte
		c = s[i]
		if c == '.' {
			if isDot {
				return len(buff), errors.New("Invalid domain name")
			}
			isDot = true
			sectionLen := i - ptr
			buff[off] = byte(sectionLen)
			copy(buff[off+1:], s[ptr:i])
			off += sectionLen + 1
			ptr = i + 1
		} else {
			isDot = false
		}
	}

	if off < len(buff) {
		buff[off] = 0
	}
	return off + 1, nil
}

func (dns *dnsMsg) encodeQuestion(q dnsQuestion, buff []byte, off int) (int, error) {
	off, err := encodeDomainName(q.qName, buff, off)
	if err != nil {
		return off, err
	}
	off, err = encodeUint16(q.qType, buff, off)
	if err != nil {
		return off, err
	}
	off, err = encodeUint16(q.qClass, buff, off)
	if err != nil {
		return off, err
	}

	return off, nil
}

func (dns *dnsMsg) encodeRecord(r dnsRecord, buff []byte, off int) (int, error) {
	off, err := encodeDomainName(r.rdName, buff, off)
	if err != nil {
		return off, err
	}

	off, err = encodeUint16(r.rdType, buff, off)
	if err != nil {
		return off, err
	}

	off, err = encodeUint16(r.rdClass, buff, off)
	if err != nil {
		return off, err
	}

	off, err = encodeUint32(r.rdTTL, buff, off)
	if err != nil {
		return off, err
	}

	off, err = encodeUint16(r.rdLength, buff, off)
	if err != nil {
		return off, err
	}

	switch r.rdType {
	case RESOURCE_RECORD_A:
		fallthrough
	case RESOURCE_RECORD_AAAA:
		fallthrough
	case RESOURCE_RECORD_TXT:
		for i := 0; i < int(r.rdLength); i++ {
			off, err = encodeUint8(r.rdData[i], buff, off)
			if err != nil {
				return off, err
			}
		}
	default:
		return off, errors.New("Unsupport record type")
	}

	return off, nil
}

func (dns *dnsMsg) encodeMsg() (buf []byte, err error) {
	fmt.Println("Encode DNS msg....")
	buf = make([]byte, 1024)

	off, err := dns.encodeDnsHdr(buf, 0)
	if err != nil {
		return nil, err
	}

	for _, q := range dns.questions {
		off, err = dns.encodeQuestion(q, buf, off)
		if err != nil {
			return nil, err
		}
	}

	for _, r := range dns.answers {
		off, err = dns.encodeRecord(r, buf, off)
		if err != nil {
			return nil, err
		}
	}

	for _, r := range dns.authorities {
		off, err = dns.encodeRecord(r, buf, off)
		if err != nil {
			return nil, err
		}
	}

	for _, r := range dns.additionals {
		off, err = dns.encodeRecord(r, buf, off)
		if err != nil {
			return nil, err
		}
	}

	return buf[:off], nil
}
