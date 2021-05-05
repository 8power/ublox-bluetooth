package ubloxbluetooth

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

// Section 5.1.3 on page 30 of
// https://www.u-blox.com/sites/default/files/u-connect-ATCommands-Manual_%28UBX-14044127%29.pdf
// states that a delay of 50ms is required before start of data transmission.
func modeSwitchDelay() {
	time.Sleep(50 * time.Millisecond)
}

// EnterDataMode sends the ATO command to set Ublox to Data Mode
func (ub *UbloxBluetooth) EnterDataMode() error {
	err := ub.Write(EnterDataModeCommand().Cmd)
	if err != nil {
		return errors.Wrap(err, "[EnterDataMode] error")
	}
	ub.currentMode = dataMode
	ub.serialPort.SetEDMFlag(true)
	modeSwitchDelay()
	return nil
}

// EnterExtendedDataMode sends the ATO2 command to set Ublox to
// Extended Data Mode (EDM)
func (ub *UbloxBluetooth) EnterExtendedDataMode() error {
	err := ub.Write(EnterExtendedDataModeCommand().Cmd)
	if err != nil {
		return errors.Wrap(err, "[EnterExtendedDataMode] error")
	}
	ub.currentMode = extendedDataMode
	ub.serialPort.SetEDMFlag(true)
	modeSwitchDelay()
	return nil
}

// EnterCommandMode sends the Escape Sequence required to return the Command Mode (AT)
func (ub *UbloxBluetooth) EnterCommandMode() error {
	err := ub.serialPort.ResetViaDTR()
	if err != nil {
		return errors.Wrap(err, "[EnterCommandMode] error")
	}
	ub.currentMode = commandMode
	ub.serialPort.SetEDMFlag(false)
	modeSwitchDelay()
	return nil
}

// ResetUblox calls the Serial port's ResetViaDTR
func (ub *UbloxBluetooth) ResetUblox() error {
	return ub.serialPort.ResetViaDTR()
}

// ResetUbloxSync calls the Serial port's ResetViaDTR and does not return until
// the ublox module has indicated it is ready
func (ub *UbloxBluetooth) ResetUbloxSync() error {
	if ub.rebootExpected {
		return fmt.Errorf("[ResetUblox] Reset outstanding error")
	}

	ub.rebootExpected = true
	err := ub.serialPort.ResetViaDTR()

	if err != nil {
		return errors.Wrap(err, "[ResetUblox] error")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
	defer cancel()

	select {
	case <-ub.rebootDetected:

	case <-ctx.Done():
		// Should take no more than a second for 750/751. 753/754 take slightly longer
		return fmt.Errorf("[ResetUblox] Reset timed out error")
	}

	return nil
}

func (ub *UbloxBluetooth) signalUbloxReboot() {
	if ub.rebootExpected {
		ub.rebootDetected <- true
		ub.rebootExpected = false
	}
}
