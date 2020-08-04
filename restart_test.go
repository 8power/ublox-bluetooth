package ubloxbluetooth

import (
	"fmt"
	"log"
	"testing"

	serial "github.com/8power/ublox-bluetooth/serial"
)

var bt *UbloxBluetooth

func handleFatal(s string, err error) {
	bt.Close()
	log.Fatalf("%s %v\n", s, err)
}

func TestResetWatchdog(t *testing.T) {
	bt, err := NewUbloxBluetooth(timeout)
	if err != nil {
		handleFatal("NewUbloxBluetooth error", err)
	}
	defer bt.Close()

	err = bt.ATCommand()
	if err != nil {
		handleFatal("AT - 0 error", err)
	}

	err = bt.ResetWatchdogConfiguration()
	if err != nil {
		fmt.Printf("ResetWatchdogConfiguration error %v\n", err)
	}
	fmt.Println("ResetWatchdogConfiguration OK")
}

func TestSetWatchdog(t *testing.T) {
	bt, err := NewUbloxBluetooth(timeout)
	if err != nil {
		handleFatal("NewUbloxBluetooth error", err)
	}
	defer bt.Close()

	err = bt.ATCommand()
	if err != nil {
		handleFatal("AT - 0 error", err)
	}

	err = bt.SetWatchdogConfiguration()
	if err != nil {
		fmt.Printf("ResetWatchdogConfiguration error %v\n", err)
	}
	fmt.Println("ResetWatchdogConfiguration OK")
}

func TestRestartViaDTR(t *testing.T) {
	var err error
	serial.SetVerbose(true)

	bt, err = NewUbloxBluetooth(timeout)
	if err != nil {
		handleFatal("NewUbloxBluetooth error", err)
	}
	defer bt.Close()

	bt.ResetUblox()

	err = bt.ATCommand()
	if err != nil {
		handleFatal("AT - 0 error", err)
	}
}

func TestRestart(t *testing.T) {
	var err error
	serial.SetVerbose(true)

	bt, err = NewUbloxBluetooth(timeout)
	if err != nil {
		handleFatal("NewUbloxBluetooth error", err)
	}
	defer bt.Close()

	err = bt.ATCommand()
	if err != nil {
		handleFatal("AT - 0 error", err)
	}

	/*err = bt.EnterExtendedDataMode()
	if err != nil {
		handleFatal("EnterExtendedDataMode error", err)
	}*/

	err = bt.ATCommand()
	if err != nil {
		handleFatal("AT - 1 error", err)
	}

	err = bt.RebootUblox()
	if err != nil {
		handleFatal("RebootUblox error", err)
	}

	/*err = bt.EnterExtendedDataMode()
	if err != nil {
		handleFatal("EnterExtendedDataMode error", err)
	}*/

	err = bt.MultipleATCommands()
	if err != nil {
		handleFatal("AT - 2 error", err)
	}
}
