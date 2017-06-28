package kr

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

type Profile struct {
	SSHWirePublicKey []byte  `json:"public_key_wire"`
	Email            string  `json:"email"`
	PGPPublicKey     *[]byte `json:"pgp_pk,omitempty"`
}

func (p Profile) AuthorizedKeyString() (authString string, err error) {
	pk, err := p.SSHPublicKey()
	if err != nil {
		return
	}
	authString = pk.Type() + " " + base64.StdEncoding.EncodeToString(p.SSHWirePublicKey) + " " + strings.Replace(p.Email, " ", "", -1)
	return
}

func (p Profile) SSHPublicKey() (pk ssh.PublicKey, err error) {
	return ssh.ParsePublicKey(p.SSHWirePublicKey)
}

func (p Profile) RSAPublicKey() (pk *rsa.PublicKey, err error) {
	return SSHWireRSAPublicKeyToRSAPublicKey(p.SSHWirePublicKey)
}

func (p Profile) PublicKeyFingerprint() []byte {
	digest := sha256.Sum256(p.SSHWirePublicKey)
	return digest[:]
}

func (p Profile) Equal(other Profile) bool {
	return bytes.Equal(p.SSHWirePublicKey, other.SSHWirePublicKey) && p.Email == other.Email
}

func (p Profile) AsciiArmorPGPPublicKey() (s string, err error) {
	if p.PGPPublicKey == nil {
		err = fmt.Errorf("no pgp public key")
		return
	}
	output := &bytes.Buffer{}
	input, err := armor.Encode(output, "PGP PUBLIC KEY BLOCK", map[string]string{"Comment": "Created With Kryptonite"})
	if err != nil {
		return
	}
	_, err = input.Write(*p.PGPPublicKey)
	if err != nil {
		return
	}
	err = input.Close()
	if err != nil {
		return
	}
	s = string(output.Bytes())
	return
}

func (p Profile) PGPPublicKeySHA1Fingerprint() (s string, err error) {
	if p.PGPPublicKey == nil {
		err = fmt.Errorf("no pgp public key")
		return
	}
	reader := bytes.NewReader(*p.PGPPublicKey)
	for {
		var pkt packet.Packet
		pkt, err = packet.Read(reader)
		if err != nil {
			break
		}
		switch pkt := pkt.(type) {
		case *packet.PublicKey:
			digest := pkt.Fingerprint[:]
			s = hex.EncodeToString(digest)
			return
		default:
			continue
		}
	}
	err = fmt.Errorf("no pgp public key packet found")
	return
}

func (p Profile) PGPPublicKeyGPGFingerprintString() (s string, err error) {
	if p.PGPPublicKey == nil {
		err = fmt.Errorf("no pgp public key")
		return
	}
	reader := bytes.NewReader(*p.PGPPublicKey)
	for {
		var pkt packet.Packet
		pkt, err = packet.Read(reader)
		if err != nil {
			break
		}
		switch pkt := pkt.(type) {
		case *packet.PublicKey:
			keyID := strings.ToUpper(pkt.KeyIdString())
			algo := pkt.PubKeyAlgo
			seconds := fmt.Sprintf("%d", pkt.CreationTime.Unix())

			fp := pkt.Fingerprint[:]
			hexFp := hex.EncodeToString(fp)

			if algo == packet.PubKeyAlgoEdDSA {
				s = "sec:u:" + "256" + ":" + fmt.Sprintf("%d", algo) + ":" + keyID + ":" + seconds + ":::u:::scSC:::+::" + "ed25519" + "::::"

			} else {
				s = "sec:u:" + "4096" + ":" + fmt.Sprintf("%d", algo) + ":" + keyID + ":" + seconds + ":::u:::scSC:::+::" + "23" + "::::"
			}

			s += "\n"
			s += "fpr:::::::::" + strings.ToUpper(hexFp) + ":"

			return
		default:
			continue
		}
	}
	err = fmt.Errorf("no pgp public key packet found")
	return

}
