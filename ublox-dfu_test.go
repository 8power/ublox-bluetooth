package ubloxbluetooth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/pkg/errors"
)

const (
	MTU_SIZE = 236
)

func Test_GetSemVer(t *testing.T) {
	btd, err := InitUbloxBluetooth(timeout, nil)
	if err != nil {
		t.Fatalf("InitUbloxBluetooth error %v", err)
	}

	ub, err := btd.GetDevice(0)
	//defer ub.Close()

	ub.serialPort.SetVerbose(true)

	err = ub.ATCommand()
	if err != nil {
		t.Errorf("AT error %v\n", err)
	}

	err = ub.EchoOff()
	if err != nil {
		t.Errorf("EchoOff error %v\n", err)
	}

	mac := os.Getenv("DEVICE_MAC")
	err = ub.ConnectToDevice(mac, func(ub *UbloxBluetooth) error {
		defer ub.DisconnectFromDevice()

		time.Sleep(20 * time.Millisecond)

		err := ub.EnableNotifications()
		if err != nil {
			return errors.Wrapf(err, "EnableNotifications failed:")
		}

		err = ub.EnableIndications()
		if err != nil {
			return errors.Wrapf(err, "EnableIndications failed:")
		}

		_, err = ub.UnlockDevice(password)
		if err != nil {
			return errors.Wrapf(err, "UnlockDevice failed:")
		}
		svn, err := ub.GetSemVerVersion()
		if err != nil {
			return errors.Wrapf(err, "GetSemVerVersion failed:")
		}
		t.Log("SemVer version is ", svn)
		return nil
	}, func(ub *UbloxBluetooth) error {
		return fmt.Errorf("Disconnected")
	})
	if err != nil {
		t.Errorf("Test Failed: %v", err)
	}
}

func Test_Dfu(t *testing.T) {
	btd, err := InitUbloxBluetooth(timeout, nil)
	if err != nil {
		t.Fatalf("InitUbloxBluetooth error %v", err)
	}

	err = btd.EncryptComms(true, "")
	if err != nil {
		t.Fatalf("EncryptComms error %v", err)
	}

	ub, err := btd.GetDevice(0)
	if err != nil {
		t.Fatalf("GetDevice(0) error %v", err)
	}
	//defer ub.Close()

	ub.serialPort.SetVerbose(true)

	err = ub.ATCommand()
	if err != nil {
		t.Errorf("AT error %v\n", err)
	}

	err = ub.EchoOff()
	if err != nil {
		t.Errorf("EchoOff error %v\n", err)
	}

	mac := os.Getenv("DEVICE_MAC")
	err = ub.ConnectToDevice(mac, func(ub *UbloxBluetooth) (e error) {
		dfu_in_progress := false
		upgrade_issued := false

		defer func() {
			if e != nil {
				if dfu_in_progress {
					ub.DfuAbort()
				}
			}
			if !upgrade_issued {
				ub.DisconnectFromDevice()
			}
		}()

		time.Sleep(20 * time.Millisecond)

		err := ub.EnableNotifications()
		if err != nil {
			return errors.Wrapf(err, "EnableNotifications failed:")
		}

		err = ub.EnableIndications()
		if err != nil {
			return errors.Wrapf(err, "EnableIndications failed:")
		}

		_, err = ub.UnlockDevice(password)
		if err != nil {
			return errors.Wrapf(err, "UnlockDevice failed:")
		}

		// Derive an ephemeral public/private keypair for performing ECDHE with
		// the recipient.
		ephemeralPrivKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return errors.Wrapf(err, "Generate private key failed:")
		}
		ephemeralPubKey := ephemeralPrivKey.PubKey().SerializeUncompressed()

		remotePubKey, err := ub.ExchangeECDHPublicKeys(ephemeralPubKey[1:])
		if err != nil {
			return errors.Wrapf(err, "ExchangeECDHPublicKeys failed:")
		}

		// Convert Leaf Public key into secp256k1 module public key (Add the format byte for uncompressed pub key format)
		formattedPublicKey := append([]byte("\004"), remotePubKey...)

		remotePK, err := secp256k1.ParsePubKey(formattedPublicKey)
		if err != nil {
			return errors.Wrapf(err, "ParsePubKey failed:")
		}

		sharedSecret := secp256k1.GenerateSharedSecret(ephemeralPrivKey, remotePK)

		t.Log("My public Key     \r\n", hex.Dump(ephemeralPubKey[1:]))
		t.Log("Sensor public Key \r\n", hex.Dump(remotePubKey))
		t.Log("Shared secret     \r\n", hex.Dump(sharedSecret))

		// Create a psuedo executable
		rand.Seed(time.Now().Unix())
		psuedoCode := make([]byte, 32768-aes.BlockSize-rand.Intn(14)-1)
		for i := 0; i < len(psuedoCode); i++ {
			psuedoCode[i] = byte(i % 256)
		}
		psuedoCode = pkcs7Pad(psuedoCode, aes.BlockSize)

		// Prep encrypted output
		key := sharedSecret[:16]
		block, err := aes.NewCipher(key)
		if err != nil {
			return errors.Wrapf(err, "aes.NewCipher failed:")
		}
		encryptedCode := make([]byte, len(psuedoCode)+aes.BlockSize)
		iv := encryptedCode[:aes.BlockSize]
		crand.Read(iv)
		imageLength := len(encryptedCode)
		if imageLength > 32768 {
			t.Errorf("Image too large to fit into flash")
		}

		// Do the encryption
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(encryptedCode[aes.BlockSize:], psuedoCode)

		// Calculate hash and signature
		hash := sha256.Sum256(encryptedCode[:])
		sign := ecdsa.Sign(ephemeralPrivKey, hash[:])

		// verify its kosher
		if sign.Verify(hash[:], ephemeralPrivKey.PubKey()) == false {
			return errors.Wrapf(err, "sign.Verify failed:")
		}

		signature := sign.Serialize()
		t.Log("DER Signature     \r\n", hex.Dump(signature[:]))

		var r []byte
		var s []byte

		// Convert from DER to 64byte (r,s) format
		rLen := int(signature[3])
		switch rLen {
		case 0x20:
			r = signature[4:36]
			s = signature[38:70]
		case 0x21:
			r = signature[5:37]
			s = signature[39:71]
		default:
			t.Errorf("Invalid DER signature")
		}

		rs := append(r, s...)

		var sig [64]byte
		copy(sig[:], rs[:])

		var ver [32]byte
		version := "v1.2.3\u0000" // Make it a C string
		copy(ver[:], version)

		dp := &DfuParams{
			ImgFlags:      0x01, // Psuedo Application
			DfuCtx:        1,
			MtuSize:       MTU_SIZE,
			StartingSeqNo: 0,
			HashSha256:    hash,
			Signature:     sig,
			ImgQspiOffset: 156,
			ImgLength:     uint32(imageLength),
			ImgVersion:    ver,
			CodeBase:      0x000f0000, // Top 32K of application space so we don't overwrite the code under test
			SdVersion:     0xCA,       // s140_nrf52_7.0.1
		}

		t.Log("HashSha256        \r\n", hex.Dump(hash[:]))
		t.Log("Signature         \r\n", hex.Dump(sig[:]))
		t.Log("ImgVersion        \r\n", hex.Dump(ver[:]))

		_, err = ub.DfuInit(dp)
		if err != nil {
			return errors.Wrapf(err, "ub.DfuInit failed:")
		}
		dfu_in_progress = true

		var seq_no uint16 = 0
		offset := 0
		size := MTU_SIZE
		for imageLength > 0 {
			if imageLength < MTU_SIZE {
				size = imageLength
			}

			next_seq_no, err := ub.DfuPacket(seq_no, encryptedCode[offset:offset+size])
			if err != nil {
				return errors.Wrapf(err, "ub.DfuPacket failed:")
			}

			if next_seq_no != seq_no+1 {
				t.Errorf("Invalid Sequence number")
			}

			offset += MTU_SIZE
			seq_no++
			imageLength -= MTU_SIZE
		}

		err = ub.DfuXferDone()
		if err != nil {
			return errors.Wrapf(err, "ub.DfuXferDone failed:")
		}
		dfu_in_progress = false

		err = ub.DfuUpgrade()
		if err != nil {
			return errors.Wrapf(err, "ub.DfuUpgrade failed:")
		}

		upgrade_issued = true
		return nil
	}, func(ub *UbloxBluetooth) error {
		return fmt.Errorf("Disconnected")
	})
	if err != nil {
		t.Errorf("Test Failed: %v", err)
	}
}

func pkcs7Pad(b []byte, blocksize int) []byte {
	if len(b)%blocksize == 0 {
		return b
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
}

func Test_ECDHprotocol(t *testing.T) {
	// Derive an ephemeral public/private keypair for performing ECDHE with
	my_pvt_key := "eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694"
	others_public_key := "C4EC90A94EA2D690952644FE8AA8C79D7DDF9B4B2D92A15018674C1A50E45088977EFA1F08E7656041333DE278DD2DAF8878165BFB962273260F1D5BC8373A64"
	raw_data := []byte("0123456789abcdef0123456789abcdef0123456789abcdef")

	prk, _ := hex.DecodeString(my_pvt_key)
	PrivKey := secp256k1.PrivKeyFromBytes(prk)
	PubKey := PrivKey.PubKey().SerializeUncompressed()

	// Convert Leaf Public key into secp256k1 module public key (Add the format byte for uncompressed pub key format)
	fpk, _ := hex.DecodeString(others_public_key)
	formattedPublicKey := append([]byte("\004"), fpk...)

	remotePK, err := secp256k1.ParsePubKey(formattedPublicKey)
	if err != nil {
		t.Errorf("ParsePubKey failed: %v", err)
	}

	sharedSecret := secp256k1.GenerateSharedSecret(PrivKey, remotePK)

	t.Log("My private Key    \r\n", my_pvt_key)
	t.Log("My public Key     \r\n", hex.Dump(PubKey[1:]))
	t.Log("Others public Key \r\n", hex.Dump(remotePK.SerializeUncompressed()[1:]))
	t.Log("Shared secret     \r\n", hex.Dump(sharedSecret))
	t.Log("Raw Data          \r\n", hex.Dump(raw_data))

	// Calculate hash and signature
	hash := sha256.Sum256(raw_data[:])
	sign := ecdsa.Sign(PrivKey, hash[:])

	// verify its kosher
	if sign.Verify(hash[:], PrivKey.PubKey()) == false {
		t.Log("sign.Verify failed:")
	}

	signature := sign.Serialize()
	t.Log("DER Signature     \r\n", hex.Dump(signature[:]))

	var r []byte
	var s []byte

	// Convert from DER to 64byte (r,s) format
	rLen := int(signature[3])
	switch rLen {
	case 0x20:
		r = signature[4:36]
		s = signature[38:70]
	case 0x21:
		r = signature[5:37]
		s = signature[39:71]
	default:
		t.Errorf("Invalid DER signature")
	}

	sig2 := append(r, s...)

	t.Log("r         \r\n", hex.Dump(r[:]))
	t.Log("s         \r\n", hex.Dump(s[:]))

	t.Log("HashSha256        \r\n", hex.Dump(hash[:]))
	t.Log("Signature         \r\n", hex.Dump(sig2[:]))

	/*
		// Create a psuedo executable
		rand.Seed(time.Now().Unix())
		psuedoCode := make([]byte, 32768-rand.Intn(14)-1)
		crand.Read(psuedoCode)
		imageLength := len(psuedoCode)
		psuedoCode = pkcs7Pad(psuedoCode, aes.BlockSize)

		// Prep encrypted output
		key := sharedSecret[:16]
		block, err := aes.NewCipher(key)
		if err != nil {
			return errors.Wrapf(err, "aes.NewCipher failed:")
		}
		encryptedCode := make([]byte, len(psuedoCode)+aes.BlockSize)
		iv := encryptedCode[:aes.BlockSize]
		crand.Read(iv)

		// Do the encryption
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(encryptedCode[aes.BlockSize:], psuedoCode)

		// Calculate hash and signature
		hash := sha256.Sum256(encryptedCode[:])
		sign := ecdsa.Sign(ephemeralPrivKey, hash[:])

		// verify its kosher
		if sign.Verify(hash[:], ephemeralPrivKey.PubKey()) == false {
			return errors.Wrapf(err, "sign.Verify failed:")
		}

		signature := sign.Serialize()
		var s [64]byte
		copy(s[:], signature[:])

		var ver [32]byte
		version := "v1.2.3\u0000" // Make it a C string
		copy(ver[:], version)

		dp := &DfuParams{
			ImgFlags:      0x01, // Psuedo Application
			DfuCtx:        1,
			MtuSize:       236,
			StartingSeqNo: 0,
			HashSha256:    hash,
			Signature:     s,
			ImgQspiOffset: 156,
			ImgLength:     uint32(imageLength),
			ImgVersion:    ver,
			CodeBase:      0x000f0000, // Top 32K of application space so we don't overwrite the code under test
			SdVersion:     0xCA,       // s140_nrf52_7.0.1
		}

		t.Log("HashSha256        \r\n", hex.Dump(hash[:]))
		t.Log("Signature         \r\n", hex.Dump(s[:]))
		t.Log("ImgVersion        \r\n", hex.Dump(ver[:]))
		0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
		fc7913e6b7a2c371515b70ac6c27fa44f1f6a05bd4bae833f022af93c7b54c4b22a7df25e1b449a366eda289d3a2060241e5302d821e32dc4082dc0cdcb03ed9
	*/
}
