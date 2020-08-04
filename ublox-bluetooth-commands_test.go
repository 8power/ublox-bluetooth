package ubloxbluetooth

import (
	"fmt"
	"testing"

	serial "github.com/8power/ublox-bluetooth/serial"
	"github.com/fortytw2/leaktest"
	"github.com/pkg/errors"
)

type DownloadSequence struct {
	Sequence   int
	ToDownload bool
}

type DownloadSequences struct {
	Array []DownloadSequence
}

func NewDownloadSequences() DownloadSequences {
	return DownloadSequences{
		Array: []DownloadSequence{},
	}
}

func (s *DownloadSequences) GetDownloadList(currentSequenceNumber int, count int, lastSequenceRead int) []int {
	startingSequenceNumber := int(currentSequenceNumber - count)
	if lastSequenceRead == 0 {
		for i := startingSequenceNumber; i <= currentSequenceNumber; i++ {
			ds := DownloadSequence{
				Sequence:   i,
				ToDownload: true,
			}
			s.Array = append(s.Array, ds)
		}
	} else {
		cutPoint := 0
		for i := 0; i <= len(s.Array)/2; i++ {
			if s.Array[i].ToDownload {
				cutPoint = i
				break
			}
		}

		if cutPoint > 0 {
			s.Array = s.Array[cutPoint:]
		}
	}

	downloadList := []int{}
	lenSeq := len(s.Array) - 1
	for i := 0; i < lenSeq; i++ {
		if s.Array[i].ToDownload {
			downloadList = append(downloadList, s.Array[i].Sequence)
		}
		if len(downloadList) > 9 {
			break
		}
	}

	if s.Array[lenSeq].ToDownload {
		if downloadList[len(downloadList)-1] != s.Array[lenSeq].Sequence {
			downloadList = append(downloadList, s.Array[lenSeq].Sequence)
		}
	}
	return downloadList
}

func (s *DownloadSequences) UpdateDownloaded(downloaded []int) {

}

func TestUbloxBluetoothCommands(t *testing.T) {
	defer leaktest.Check(t)()
	serial.SetVerbose(true)
	ub, err := setupBluetooth()
	if err != nil {
		t.Fatalf("setupBluetooth error %v\n", err)
	}
	defer ub.Close()

	err = connectToDevice("FFA73E733B27r", func(t *testing.T) error {
		version, err := ub.GetVersion()
		if err != nil {
			t.Fatalf("GetVersion error %v\n", err)
		}
		fmt.Printf("[GetVersion] replied with: %v\n", version)

		serialNumber, err := ub.ReadSerialNumber()
		if err != nil {
			t.Fatalf("ReadSerialNumber error %v\n", err)
		}
		fmt.Printf("[ReadSerialNumber] replied with: %s\n", serialNumber)

		fmt.Printf("[GetTime] starting\n")
		time, err := ub.GetTime()
		if err != nil {
			t.Errorf("GetTime error %v\n", err)
		}
		fmt.Printf("[GetTime] Current timestamp %d\n", time)

		config, err := ub.ReadConfig()
		if err != nil {
			t.Fatalf("ReadConfig error %v\n", err)
		}
		fmt.Printf("[ReadConfig] replied with: %v\n", config)

		echo, err := ub.EchoCommand("012345678901234567890123456789012345678901234567890123456789")
		if err != nil {
			t.Fatalf("EchoCommand error %v\n", err)
		}
		fmt.Printf("[EchoCommand] replied with: %v\n", echo)

		info, err := ub.ReadRecorderInfo()
		if err != nil {
			t.Fatalf("ReadRecorderInfo error %v\n", err)
		}
		fmt.Printf("[ReadRecorderInfo] SequenceNo: %d. Count: %d. SlotUsage: %d. PoolUsage: %d.\n", info.SequenceNo, info.Count, info.SlotUsage, info.PoolUsage)

		/*
			var lastSequenceRead uint32
			dataSequences := []uint32{}

			err = ub.ReadRecorder(0, func(e *VehEvent) error {
				fmt.Printf("Sequence: %d\n", e.Sequence)
				lastSequenceRead = e.Sequence
				if e.DataFlag {
					dataSequences = append(dataSequences, e.Sequence)
				}
				return nil
			})
			if err != nil {
				t.Errorf("ReadRecorder error %v\n", err)
			}
			fmt.Printf("[ReadRecorder] Final Sequence %d events\n", lastSequenceRead)
			fmt.Printf("[ReadRecorder] has %d data sequences to download\n", len(dataSequences))

			for _, s := range dataSequences {
				meta, err := ub.QueryRecorderMetaDataCommand(s)
				if err != nil {
					t.Errorf("QueryRecorderMetaDataCommand error %v", err)
				} else {
					fmt.Printf("Metadata - Valid: %t\tLength: %d\tCRC: %X", meta.Valid, meta.Length, meta.Crc)
					if meta.Valid {

					}
				}
			}

			err = ub.DisconnectFromDevice()
			if err != nil {
				t.Errorf("DisconnectFromDevice error %v\n", err)
			}*/
		return err
	}, ub, t)
	if err != nil {
		t.Errorf("exerciseTheDevice error %v\n", err)
	}

}

func TestPagedDownloads(t *testing.T) {
	ub, err := setupBluetooth()
	if err != nil {
		t.Fatalf("setupBluetooth error %v\n", err)
	}
	defer ub.Close()

	err = connectToDevice("EE9EF8BA058Br", func(t *testing.T) error {
		defer ub.DisconnectFromDevice()

		err := ub.EnableNotifications()
		if err != nil {
			t.Fatalf("EnableNotifications error %v\n", err)
		}

		time, err := ub.GetTime()
		if err != nil {
			t.Errorf("GetTime error %v\n", err)
		}
		fmt.Printf("[GetTime] Current timestamp %d\n", time)
		serial.SetVerbose(true)
		return err
	}, ub, t)

	if err != nil {
		t.Errorf("TestPagedDownloads error %v\n", err)
	}
}

func TestAttemptToConnectToMissing(t *testing.T) {
	ub, err := setupBluetooth()
	if err != nil {
		t.Fatalf("setupBluetooth error %v\n", err)
	}
	defer ub.Close()

	err = connectToDevice("EEEEEEEEEEEEr", func(t *testing.T) error {
		defer ub.DisconnectFromDevice()
		ub.PeerList()
		return nil
	}, ub, t)
	if err != nil {
		t.Errorf("TestReboot error %v\n", err)
	}

	err = connectToDevice("CE1A0B7E9D79r", func(t *testing.T) error {
		defer ub.DisconnectFromDevice()
		ub.PeerList()
		return nil
	}, ub, t)
	if err != nil {
		t.Errorf("TestReboot error %v\n", err)
	}
}

func TestRebootUblox(t *testing.T) {
	ub, err := setupBluetooth()
	if err != nil {
		t.Fatalf("setupBluetooth error %v\n", err)
	}
	defer ub.Close()

	err = connectToDevice("EE9EF8BA058Br", func(t *testing.T) error {
		defer ub.DisconnectFromDevice()
		ub.PeerList()
		return nil
	}, ub, t)
	if err != nil {
		t.Errorf("TestReboot error %v\n", err)
	}

	err = ub.RebootUblox()
	if err != nil {
		t.Errorf("RebootUblox error %v\n", err)
	}
	fmt.Printf("Rebooted")
}

func setupBluetooth() (*UbloxBluetooth, error) {
	ub, err := NewUbloxBluetooth(timeout)
	if err != nil {
		return nil, errors.Wrap(err, "NewUbloxBluetooth error")
	}

	err = ub.ConfigureUblox(timeout)
	if err != nil {
		return nil, errors.Wrap(err, "ConfigureUblox error")
	}

	err = ub.RebootUblox()
	if err != nil {
		return nil, errors.Wrap(err, "RebootUblox error")
	}

	err = ub.ATCommand()
	if err != nil {
		return nil, errors.Wrap(err, "AT error")
	}

	err = ub.EchoOff()
	if err != nil {
		return nil, errors.Wrap(err, "EchoOff error")
	}

	err = ub.ATCommand()
	if err != nil {
		return nil, errors.Wrap(err, "AT error")
	}

	return ub, nil
}

type TestFunc func(*testing.T) error

func connectToDevice(mac string, tfn TestFunc, ub *UbloxBluetooth, t *testing.T) error {
	return ub.ConnectToDevice(mac, func() error {
		err := ub.EnableNotifications()
		if err != nil {
			t.Fatalf("EnableNotifications error %v\n", err)
		}

		err = ub.EnableIndications()
		if err != nil {
			t.Fatalf("EnableIndications error %v\n", err)
		}

		unlocked, err := ub.UnlockDevice(password)
		if err != nil {
			t.Fatalf("UnlockDevice error %v\n", err)
		}
		if !unlocked {
			t.Fatalf("UnlockDevice error - failed to unlock")
		}

		return tfn(t)
	}, func() error {
		fmt.Println("Disconnected!")
		return nil
	})
}
