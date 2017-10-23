package rocacheck

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

var bad = []string{
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlze9c7qGdjDLVR/ntk+4
ZkfMcYsAnmfTFHfe3Xv7jRQqPCXCULtr0y0jG3aRJmEenoXO9uDveqr43gFB9yvA
dLEhu0aJqpB7lNZ+yXsvfVp/96dkSN8oWYL/dd9Z7GQOvVniHUY3Xsd7zdw2eYOy
HSXhhA2Ttwnj3c1jEYfC0y9q1cU99aL0ogGDqolcOvlkJu+mGb+6+WyboFa1gwRu
kYxBHZWKiHCt/eihvXsPTzTlXmTXWdGJtA1xZDnCBWuZ90b5R0agXVIESTl0cCyH
aQM/tLZmktJIU+Eu7ALBXemPg9kh3SCnYd3/YvDGCtYSXOWthHwlP5CImRBcQaNn
cQIDAQAB
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnDSwGO+LetuWIPxBrWIV
EZhfr8VB7tnXBnFaNev61bT1lViBUAN8rmMBw2rd/a6Lw4SjDi+3Fc7hpQtccMyr
z3Z52VVsuS1Df94/2GJ2J+B8qw0dTHQoVjPGaOrRads5cjrI1fvgcKNhfwXHd8jh
6fCHwVIruU8E2wgTu91ceTzAODzCe1aWbE0QMYTV11E0t2+vt808AWsYMDOWMIOa
0sFZD1DzQSw1YC74YV92yDGsHA4JNZVl6JB0H21lxENKrkOF9MJx+doXHiEEfwNC
3F7kf2QDd+3oyRcrrGZt9rhfRPQckUnYM495nfaQcHzTXyIySnY0s6PkwbgL4B44
dQIDAQAB
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkVOD39Rao7yBD5Msly74
VCZzikzRV672cEkNEM6GB3wg15W7Nw9NxdzwlzBNB5fb/FXL3hd9m9djNkrd2fj6
FG47dS4A9nK1b+KL7E+Yhh19MP1GKxz3cW8sTg516fpvvnvPKUcRyyIOxARvvhuv
s7tza/I7VjIBQSHpBKuiFBkJ5yeVq3iRuiuVnNMut+MllVSEeLEoNCmDAvRI7tTK
Xtlap1sPXb93D0x2LnzlNx/5jKSorQo2nPS4iwE8UPBGE6TRMr3ap9bjTG9tP0kE
sHuM/OWBF1whlCvb/88BmE0x6v22i6ss3q/mkVt1bH0R+pgLaiRakJW7Zsgpa+sx
PQIDAQAB
-----END PUBLIC KEY-----`,
}

var good = []string{
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtA+5PaMwafUZVIU0kXo+
u3EbF45Sw+11yOuYReWxp5dGLCmqk6Ukq+PvZ9Ygq7xrOQzuUx/dY1rFqB0tz3Z4
KurqpK/aVwj+nEhRckEAtbls9qeGcMxdTgPvf8KJbjR6gw0jXdQKeLTIojXNtUSF
PpOm0tsAT0SAqGHZF9jFzBOHlpyyhiWvtZpZaUQMXRQwoptaHug7tPBjZHm3n+ba
JH8TVua9Kx8zVsrGBzZnGh7Ybap9ZxvNg2m0BMi/jMhoNr7c3eQBrrkcxqrb0GId
Hbg94w9W7Ds3v01FPb6qjKbW8Z2ZAm1lGM/3imodT8z3hLXYDUGWXUTGuaRWWKr8
+QIDAQAB
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwYtbVJUsNAQL//ijcypw
o40yK5QLJuOvwVnVSy7Q6MVlmaSv4ZQyVR5QJf2kAbBVIFK7xogMW474R9TTyvL+
iWjIpdYWF5OILlYBp/dcwqqic1ZZQnUL9ACsProq1b1kaBmpQegwD38O1F64eOPk
3GdjJo8/vQLuVfK1wFq90VnyszDuvP1PXo7g91jrwIeeqQ14+J1vYmTI8qpodNJE
VDlfQbaQB0DtSDcNcVLQCumKYSU1+8P8fSqve7TRBJtRjBXg/aliF1+twJ+ROFaJ
Yo87+pJ2Leh/L1+KqZHxPnGpCoZKKX1nqpmqy4MnE1qE37ACYEcPauI7oMFYXmoh
bwIDAQAB
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1p2IZ0HNzhtIJ4PSRe+A
mAZ9PJj4ufBmu9yZd2DgXoWQJjYnSBC1E93KUr3Kdrywpi1OqUe5XhMjIJIIiykK
7QuKbcWNEjPPMHFPi8Jw6HGToZZT/IfAJib3pY9FcmzNWyU176Zxx6HamoHUhnhp
E4gvK2h9dwpG7pejhk61lgUqQ20RIAsKa83rsLdkb2gthorVdzWd2zMO1mZc/qgl
I6xQc9yMwMpEDg2LpEq8FHpDvCqNAtdk7y4keXyMYQ+9Gz4OOGlhD7Q5KsIAXTeU
QDetJfwQwYq+tHrt7PfoBhFxV1iIvSDzfy5GtrotcDgEXsktLt14zRSmzv2R/svv
zQIDAQAB
-----END PUBLIC KEY-----`,
}

func decode(s string) *rsa.PublicKey {
	b, _ := pem.Decode([]byte(s))
	k, _ := x509.ParsePKIXPublicKey(b.Bytes)
	return k.(*rsa.PublicKey)
}

func TestKeys(t *testing.T) {
	for i, p := range bad {
		if !IsWeak(decode(p)) {
			t.Errorf("expected %d to fail", i)
		}
	}
	for i, p := range good {
		if IsWeak(decode(p)) {
			t.Errorf("expected %d to pass", i)
		}
	}
}

func BenchmarkIsWeak(b *testing.B) {
	k := decode(bad[1])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsWeak(k)
	}
}
