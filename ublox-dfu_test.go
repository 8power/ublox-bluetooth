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

func Test_ECDHexchange(t *testing.T) {
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

		_, err = ub.DfuInit(dp)
		if err != nil {
			return errors.Wrapf(err, "ub.DfuInit failed:")
		}

		err = ub.DfuAbort()
		if err != nil {
			return errors.Wrapf(err, "ub.DfuInit failed:")
		}

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
	*/
}
