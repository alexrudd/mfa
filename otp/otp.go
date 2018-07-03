package otp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

func GetTotp(secret string) string {
	key, _ := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	hash := hmac.New(sha1.New, key)
	t := new(bytes.Buffer)
	binary.Write(t, binary.BigEndian, time.Now().Unix()/30)
	hash.Write(t.Bytes())

	h := hash.Sum(nil)
	o := h[len(h)-1] & 0xf
	c := int32(h[o]&0x7f)<<24 | int32(h[o+1])<<16 | int32(h[o+2])<<8 | int32(h[o+3])
	return fmt.Sprintf("%010d", c%100000000)[4:10]
}
