package ubloxbluetooth

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/8power/ublox-bluetooth/serial"
)

func TestRSSIDataBytes(t *testing.T) {
	pl := []byte{0xaa, 0x00, 0x0b, 0x00, 0x45, 0x0d, 0x0a, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x0d, 0x0a, 0x55}
	cmd := NewEMDCmdBytes(pl)
	if cmd[0] != serial.EDMStartByte {
		t.Errorf("Does not start correctly")
	}

	if cmd[len(cmd)-1] != serial.EDMStopByte {
		t.Errorf("Does not end correctly")
	}
	fmt.Printf("Thing: %s\n", cmd)
}
func TestNewEMDCmdBytes(t *testing.T) {
	pl := []byte{0x00, 0x11, 0x03, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x66}
	cmd := NewEMDCmdBytes(pl)

	if cmd[0] != serial.EDMStartByte {
		t.Errorf("Does not start correctly")
	}

	if cmd[len(cmd)-1] != serial.EDMStopByte {
		t.Errorf("Does not end correctly")
	}

	pl = []byte{0xAA, 0x00, 0x05, 0x00, 0x44, 0x41, 0x54, 0x0D, 0x55}
	fmt.Printf("Belhold: %x\n", cmd)

	atCmd := ATCommand()
	cmd = NewEDMATCommand(atCmd.Cmd)

	if cmd[0] != serial.EDMStartByte {
		t.Errorf("Does not start correctly")
	}

	if cmd[len(cmd)-1] != serial.EDMStopByte {
		t.Errorf("Does not end correctly")
	}

	if !bytes.Equal(cmd, pl) {
		t.Errorf("Output is incorrect:\n[%x] should be [%x]", cmd, pl)
	}

	fmt.Printf("Belhold: %x\n", cmd)
}
