package ubloxbluetooth

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/8power/ublox-bluetooth/serial"
	"github.com/pkg/errors"
)

var (
	// ErrBothScansFailed returned if both device scans failed
	ErrBothScansFailed = fmt.Errorf("Both bluetooth scans failed")

	// ErrBothScansFailed returned if one of the two device scans failed
	ErrOneOfTheScansFailed = fmt.Errorf("One of the bluetooth scans failed")
)

func (ub *UbloxBluetooth) writeAndWait(r CmdResp, waitForData bool) ([]byte, error) {
	err := ub.Write(r.Cmd)
	if err != nil {
		return nil, err
	}
	return ub.WaitForResponse(r.Resp, waitForData)
}

// ATCommand issues a straight AT command - used to test connection
func (ub *UbloxBluetooth) ATCommand() error {
	_, err := ub.writeAndWait(ATCommand(), false)
	return err
}

// MultipleATCommands sends upto 5 AT commands - used to ensure stable connection.
func (ub *UbloxBluetooth) MultipleATCommands() error {
	var e error
	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		err := ub.ATCommand()
		if err == nil {
			return nil
		}
		e = errors.Wrapf(e, "AT Command error %v", err)
	}
	return fmt.Errorf("Failed after 5 attempts %v", e)
}

// getSerialNumber retrieves the serial number of the dongle
func (ub *UbloxBluetooth) getSerialNumber() (string, error) {
	sn, err := ub.writeAndWait(GetSerialCommand(), true)
	if err != nil {
		return "", err
	}

	lines := bytes.Split(sn, []byte("\r\n"))
	if len(lines) > 0 {
		return strings.Trim(string(lines[0]), "\""), nil
	}

	return "Unknown", nil
}

// getLocalName retrieves the local name of the dongle (which will be set to the 8power 16 digit serial number)
func (ub *UbloxBluetooth) getLocalName() (string, error) {
	sn, err := ub.writeAndWait(GetLocalName(), true)
	if err != nil {
		return "", err
	}

	lines := bytes.Split(sn, []byte("\r\n"))
	if len(lines) > 0 {
		return strings.Trim(string(lines[0]), "\""), nil
	}

	return "Unknown", nil
}

// EchoOff requests that the ublox device is a little less noisy
func (ub *UbloxBluetooth) EchoOff() error {
	_, err := ub.writeAndWait(EchoOffCommand(), false)
	return err
}

// RebootUblox reboots the Ublox chip
func (ub *UbloxBluetooth) RebootUblox() error {
	r := RebootCommand()
	err := ub.Write(r.Cmd)
	if err != nil {
		return err
	}
	//ub.currentMode = dataMode
	_, err = ub.WaitForResponse(r.Resp, false)
	modeSwitchDelay()
	return err
}

// SetDTRBehavior configures the device to the correct DTR behaviour
func (ub *UbloxBluetooth) SetDTRBehavior() error {
	_, err := ub.writeAndWait(SetDTRBehaviorCommand(4), false)
	if err != nil {
		return errors.Wrap(err, "SetDTRBehaviorCommand error")
	}

	_, err = ub.writeAndWait(BLEStoreConfig(), false)
	if err != nil {
		return errors.Wrap(err, "BLEStoreConfig error")
	}
	return nil
}

// PeerList returns a list of connected peers.
func (ub *UbloxBluetooth) PeerList() error {
	d, err := ub.writeAndWait(PeerListCommand(), true)
	if err != nil {
		return err
	}

	fmt.Printf("RESULT: %s [%X]\n", d, d)

	return nil
}

// DiscoveryReplyCallback function is called for each DiscoveryReply
type DiscoveryReplyCallback func(*DiscoveryReply, int32) error

func (ub *UbloxBluetooth) handleDiscovery(expResp string, drChan chan *DiscoveryReply) error {
	return ub.HandleDiscovery(expResp, func(d []byte) (bool, error) {
		dr, err := ProcessDiscoveryReply(d)
		dr.DongleIndex = ub.GetDeviceIndex()
		if err == nil {
			drChan <- dr
		} else if err != ErrorUnexpectedResponse {
			return false, err
		}
		return true, nil
	})
}

// ErrorContextCancelled returned if the Context is cancelled
var ErrorContextCancelled = fmt.Errorf("Context Cancelled")

// MultiDiscoverWithContext runs scans on all devices in parallel
func (btd *BluetoothDevices) MultiDiscoverWithContext(ctx context.Context, scantime time.Duration, drChan chan *DiscoveryReply) error {
	var err error
	noOfDevices := btd.DeviceCount()
	errChan := make(chan error, noOfDevices)

	btd.ForEachDevice(func(ub *UbloxBluetooth) error {
		go ub.discoveryCommandWithContext(ctx, scantime, drChan, errChan)
		return nil
	})

	// Don't concatenate errors. We need to spot the ContextCancelled error
	err = <-errChan
	if noOfDevices == 2 {
		err2 := <-errChan

		if err2 != nil {
			if err != nil {
				return ErrBothScansFailed
			} else {
				return ErrOneOfTheScansFailed
			}
		} else if err != nil {
			return ErrOneOfTheScansFailed
		}
	}

	return err
}

// discoveryCommandWithContext issues discovery command and handles the replies, with a context to cancel
func (ub *UbloxBluetooth) discoveryCommandWithContext(ctx context.Context, scantime time.Duration, drChan chan *DiscoveryReply, ec chan error) {
	scanPeriod := int(scantime / time.Millisecond)
	dc := DiscoveryCommand(scanPeriod)
	err := ub.Write(dc.Cmd)
	if err != nil {
		ec <- err
	} else {
		errChan := make(chan error, 1)
		go func() {
			errChan <- ub.handleDiscovery(dc.Resp, drChan)
		}()

		select {
		case e := <-errChan:
			ec <- e
		case <-ctx.Done():
			ec <- ErrorContextCancelled
		}
	}
}

// ConnectToDevice attempts to connect to the device with the specified address.
func (ub *UbloxBluetooth) ConnectToDevice(address string, onConnect DeviceEvent, onDisconnect DeviceEvent) (err error) {
	var d []byte
	var cr *ConnectionReply

	d, err = ub.writeAndWait(ConnectCommand(address), true)
	if err != nil {
		return err
	}

	// Flush out disconnect request - Bug in current Nina firmware.
	err = ub.ATCommand()
	if err != nil {
		return err
	}

	cr, err = NewConnectionReply(string(d))
	if err != nil {
		return err
	}

	defer func(mac string, start time.Time, startStats *serial.SerialPortStats) {
		elapsed := time.Since(start)
		finishStats := ub.GetSerialPortStats()
		stats, ok := ub.CommsStats[mac]
		if !ok {
			ub.CommsStats[mac] = &SensorCommsStatitics{
				TotalBytesRxed:    uint64(0),
				TotalBytesTxed:    uint64(0),
				TotalConnections:  uint64(0),
				ConnectionsFailed: uint64(0),
				TimeCommunicating: time.Duration(0),
			}
			stats = ub.CommsStats[mac]
		}
		stats.TotalBytesRxed += finishStats.RxBytes - startStats.RxBytes
		stats.TotalBytesTxed += finishStats.TxBytes - startStats.TxBytes
		stats.TimeCommunicating += elapsed
		stats.TotalConnections++
		if err != nil {
			stats.ConnectionsFailed++
		}
	}(address, time.Now(), ub.GetSerialPortStats())

	ub.connectedDevice = cr
	ub.disconnectHandler = onDisconnect
	ub.disconnectExpected = false
	ub.disconnectCount = 0
	return onConnect(ub)
}

// DisconnectFromDevice issues the disconnect command using the handle from the ConnectionReply
func (ub *UbloxBluetooth) DisconnectFromDevice() error {
	if ub.connectedDevice == nil {
		return fmt.Errorf("ConnectionReply is nil")
	}

	if ub.disconnectCount < 1 {
		ub.disconnectCount++
		ub.disconnectExpected = true

		d, err := ub.writeAndWait(DisconnectCommand(ub.connectedDevice.Handle), true)
		if err != nil {
			return err
		}

		ok, err := ProcessDisconnectReply(d)
		if !ok {
			return fmt.Errorf("Incorrect disconnect reply %q", d)
		}

		ub.connectedDevice = nil
		ub.disconnectHandler = nil
		ub.disconnectExpected = false
		return err
	}

	return fmt.Errorf("Error attempting to double disconnect")
}

// EnableIndications instructs the connected device to initialise indiciations
func (ub *UbloxBluetooth) EnableIndications() error {
	if ub.connectedDevice == nil {
		return fmt.Errorf("ConnectionReply is nil")
	}

	_, err := ub.writeAndWait(WriteCharacteristicConfigurationCommand(ub.connectedDevice.Handle, commandCCCDHandle, 2), false)
	return err
}

// EnableNotifications instructs the connected device to initialise notifications
func (ub *UbloxBluetooth) EnableNotifications() error {
	if ub.connectedDevice == nil {
		return fmt.Errorf("ConnectionReply is nil")
	}

	_, err := ub.writeAndWait(WriteCharacteristicConfigurationCommand(ub.connectedDevice.Handle, dataCCCDHandle, 1), false)
	return err
}

// ReadCharacterisitic reads the connected device's BT Characteristics
func (ub *UbloxBluetooth) ReadCharacterisitic() ([]byte, error) {
	if ub.connectedDevice == nil {
		return nil, fmt.Errorf("ConnectionReply is nil")
	}
	d, err := ub.writeAndWait(ReadCharacterisiticCommand(ub.connectedDevice.Handle, commandValueHandle), true)
	if err != nil {
		return nil, errors.Wrapf(err, "ReadCharacterisitic error")
	}
	return d, nil
}
