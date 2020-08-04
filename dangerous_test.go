package ubloxbluetooth

import (
	"testing"

	"github.com/8power/ublox-bluetooth/serial"

	"github.com/pkg/errors"
)

func TestSettingDTRAction(t *testing.T) {
	ub, err := NewUbloxBluetooth(timeout)
	if err != nil {
		t.Fatalf("NewUbloxBluetooth error %v", err)
	}
	defer ub.Close()

	serial.SetVerbose(true)
	err = ub.MultipleATCommands()
	if err != nil {
		t.Fatalf("MultipleATCommands error %v", err)
	}

	err = ub.SetDTRBehavior()
	if err != nil {
		t.Fatalf("SetDTRBehavior error %v", err)
	}

	err = ub.RebootUblox()
	if err != nil {
		t.Fatalf("RebootUblox error %v", err)
	}

	err = ub.ResetUblox()
	if err != nil {
		t.Fatalf("SetDTRBehavior error %v", err)
	}
}

func TestRebootRecorder(t *testing.T) {
	ub, err := setupBluetooth()
	if err != nil {
		t.Fatalf("setupBluetooth error %v\n", err)
	}
	defer ub.Close()

	err = connectToDevice("CE1A0B7E9D79r", func(t *testing.T) error {
		serial.SetVerbose(true)
		e := ub.RebootRecorder()
		if e != nil {
			return errors.Wrap(e, "RebootRecorder error")
		}

		e = ub.DisconnectFromDevice()
		if e != nil {
			return errors.Wrap(e, "DisconnectFromDevice error")
		}
		return nil
	}, ub, t)

	if err != nil {
		t.Errorf("TestReboot error %v\n", err)
	}
}

func TestErase(t *testing.T) {
	ub, err := setupBluetooth()
	if err != nil {
		t.Fatalf("setupBluetooth error %v\n", err)
	}
	defer ub.Close()

	err = connectToDevice("CE1A0B7E9D79r", func(t *testing.T) error {
		serial.SetVerbose(true)
		e := ub.EraseRecorder()
		if e != nil {
			return errors.Wrap(e, "EraseRecorder error")
		}
		return nil
	}, ub, t)

	if err != nil {
		t.Errorf("TestReboot error %v\n", err)
	}
}
