package ubloxbluetooth

import (
	"fmt"
	"testing"
	"time"

	"github.com/RobHumphris/rf-gateway/global"
	serial "github.com/RobHumphris/ublox-bluetooth/serial"
	retry "github.com/avast/retry-go"
	"github.com/pkg/errors"
)

var timeout = 6 * time.Second
var password = []byte{'A', 'B', 'C'}

func TestMultipleConnects(t *testing.T) {
	serial.SetVerbose(true)
	ub, err := NewUbloxBluetooth("/dev/ttyUSB0", timeout)
	if err != nil {
		t.Fatalf("NewUbloxBluetooth error %v\n", err)
	}
	defer ub.Close()

	err = ub.ConfigureUblox()
	if err != nil {
		t.Fatalf("ConfigureUblox error %v\n", err)
	}

	err = ub.RebootUblox()
	if err != nil {
		t.Fatalf("RebootUblox error %v\n", err)
	}

	err = ub.ATCommand()
	if err != nil {
		t.Errorf("AT error %v\n", err)
	}

	err = ub.EchoOff()
	if err != nil {
		t.Errorf("EchoOff error %v\n", err)
	}

	settings, err := ub.GetRS232Settings()
	if err != nil {
		t.Fatalf("GetRS232Settings error %v\n", err)
	}
	fmt.Printf("RS232 settings: %v\n", settings)

	fmt.Printf("Starting connect test ")
	for i := 0; i < 10; i++ {
		err = retry.Do(func() error {
			fmt.Printf("%03d ", i)
			//e := doConnect(ub, "C1851F6083F8r", i)
			e := doConnect(ub, "CE1A0B7E9D79r", i)
			if e != nil {
				fmt.Printf("!")
			}
			return e
		},
			retry.Attempts(global.RetryCount),
			retry.Delay(global.RetryWait))

		//doConnect(ub, "CE1A0B7E9D79r", t)
		//doConnect(ub, "D8CFDFA118ECr", t)
	}
}

func doConnect(ub *UbloxBluetooth, mac string, count int) error {
	fmt.Print("C")
	cr, err := ub.ConnectToDevice(mac)
	if err != nil {
		return errors.Wrapf(err, "TestConnect mac: %s count: %d\n", mac, count)
	}
	defer ub.DisconnectFromDevice(cr)

	time.Sleep(global.BluetoothPostConnectDelay)

	fmt.Print("N")
	err = ub.EnableNotifications(cr)
	if err != nil {
		return errors.Wrapf(err, "EnableNotifications mac: %s count: %d\n", mac, count)
	}

	fmt.Print("I")
	err = ub.EnableIndications(cr)
	if err != nil {
		return errors.Wrapf(err, "EnableIndications mac: %s count: %d\n", mac, count)
	}

	fmt.Print("U")
	_, err = ub.UnlockDevice(cr, password)
	if err != nil {
		return errors.Wrapf(err, "UnlockDevice mac: %s count: %d\n", mac, count)
	}
	fmt.Print("D\n")
	return nil
}
