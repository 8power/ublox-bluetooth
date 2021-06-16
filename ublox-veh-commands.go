package ubloxbluetooth

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
)

const readRecorderOffset = 16
const readRecorderDataOffset = 8
const maxMessageLength = 243

var (
	unlockCommand           = []byte{0x00}
	versionCommand          = []byte{0x01}
	getTimeCommand          = []byte{0x02}
	readConfigCommand       = []byte{0x03}
	writeConfigCommand      = []byte{0x04}
	readSerialNumberCommand = []byte{0x05}
	setTimeCommand          = []byte{0x07}
	abortCommand            = []byte{0x09}
	echoCommand             = []byte{0x0B}
	setSettingCommand       = []byte{0x0D}
	getSettingCommand       = []byte{0x0E}
	creditCommand           = []byte{0x11}
	recorderEraseCommand    = []byte{0x12}
	rebootCommand           = []byte{0x13}
	messageCommand          = []byte{0x14}
	recorderInfoCommand     = []byte{0x20}
	readRecorderCommand     = []byte{0x21}
	queryRecorderCommand    = []byte{0x22}
	readRecorderDataCommand = []byte{0x23}
	rssiCommand             = []byte{0x24}
	perTestCommand          = []byte{0x25}
	liveFFTCommand          = []byte{0x26}
	dfuInitCommand          = []byte{0x27}
	dfuPacketCommand        = []byte{0x28}
	dfuXferDoneCommand      = []byte{0x29}
	dfuUpgradeCommand       = []byte{0x2A}
	dfuAbortCommand         = []byte{0x2B}
	oobKeyCommand           = []byte{0x2C}
	ecdhPublicKeyCommand    = []byte{0x2D}
	getSemVerVersionCommand = []byte{0x2E}
	setConfigExtCommand     = []byte{0x80}
	getConfigExtCommand     = []byte{0x81}
)

type DfuParams struct {
	ImgFlags      uint8
	DfuCtx        uint8
	MtuSize       uint16
	StartingSeqNo uint32
	HashSha256    [32]byte
	Signature     [64]byte
	ImgQspiOffset uint32
	ImgLength     uint32
	ImgVersion    [32]byte
	CodeBase      uint32
	SdVersion     uint8
}

func (ub *UbloxBluetooth) newCharacteristicCommand(handle int, data []byte) characteristicCommand {
	return characteristicCommand{
		ub.connectedDevice.Handle,
		handle,
		data,
	}
}

func (ub *UbloxBluetooth) newCharacteristicHexCommand(handle int, data []byte, hex string) characteristicHexCommand {
	return characteristicHexCommand{
		&characteristicCommand{ub.connectedDevice.Handle, handle, data},
		hex,
	}
}

// UnlockDevice attempts to unlock the device with the password provided.
func (ub *UbloxBluetooth) UnlockDevice(password []byte) (bool, error) {
	if ub.connectedDevice == nil {
		return false, ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, append(unlockCommand, password...))
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return false, errors.Wrapf(err, "UnlockDevice error")
	}

	return ProcessUnlockReply(d)
}

// GetVersion request the connected device's version
func (ub *UbloxBluetooth) GetVersion() (*VersionReply, error) {
	if ub.connectedDevice == nil {
		return nil, ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, versionCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return nil, errors.Wrapf(err, "GetVersion error")
	}
	return NewVersionReply(d)
}

// GetTime requests the current device info.
func (ub *UbloxBluetooth) GetTime() (int32, error) {
	if ub.connectedDevice == nil {
		return -1, ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, getTimeCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return -1, errors.Wrapf(err, "GetTime error")
	}

	t, err := splitOutResponse(d, infoReply)
	if err != nil {
		return -1, err
	}

	// I hate casting something that has just been cast.
	return int32(stringToInt(t[4:12])), nil
}

// SetTime sets the current time for the device.
func (ub *UbloxBluetooth) SetTime(timestamp int32) (*TimeAdjustReply, error) {
	if ub.connectedDevice == nil {
		return nil, ErrNotConnected
	}

	tsHex := uint32ToString(uint32(timestamp))
	c := ub.newCharacteristicHexCommand(commandValueHandle, setTimeCommand, tsHex)
	d, err := ub.writeAndWait(writeCharacteristicHexCommand(c), true)
	if err != nil {
		return nil, errors.Wrapf(err, "SetTime error")
	}
	return NewTimeAdjustReply(d)
}

// ReadConfig requests the device's current config
func (ub *UbloxBluetooth) ReadConfig() (*ConfigReply, error) {
	if ub.connectedDevice == nil {
		return nil, ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, readConfigCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return nil, errors.Wrap(err, "ReadConfig error")
	}
	return NewConfigReply(d)
}

// WriteConfig sends the passed config to the device
func (ub *UbloxBluetooth) WriteConfig(cfg *ConfigReply) error {
	if ub.connectedDevice == nil {
		return ErrNotConnected
	}

	c := ub.newCharacteristicHexCommand(commandValueHandle, writeConfigCommand, cfg.ByteArray())
	_, err := ub.writeAndWait(writeCharacteristicHexCommand(c), true)
	return err
}

// ReadSerialNumber reads the serial number of the device.
func (ub *UbloxBluetooth) ReadSerialNumber() (string, error) {
	if ub.connectedDevice == nil {
		return "", ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, readSerialNumberCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return "", errors.Wrap(err, "ReadSerialNumber error")
	}
	return serialNumberReply(d)
}

// GetConfigExt gets the Extended Config
func (ub *UbloxBluetooth) GetConfigExt() ([]byte, error) {
	if ub.connectedDevice == nil {
		return nil, ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, getConfigExtCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return nil, errors.Wrapf(err, "ReadConfig error")
	}
	r := make([]byte, len(d))
	copy(r, d[1:])
	return r, nil
}

// SetConfigExt sets the Extended Config
func (ub *UbloxBluetooth) SetConfigExt(p []byte) error {
	if ub.connectedDevice == nil {
		return ErrNotConnected
	}

	c := ub.newCharacteristicHexCommand(commandValueHandle, setConfigExtCommand, hex.EncodeToString(p))
	_, err := ub.writeAndWait(writeCharacteristicHexCommand(c), true)
	return err
}

// DefaultCredit says that we can handle 16 messages in our FIFO
const DefaultCredit = 16

var defaultCreditString = uint8ToString(uint8(DefaultCredit))
var halfwayPoint = DefaultCredit

// SendCredits messages the connected device to say that it can accept `credit` number of messages
func (ub *UbloxBluetooth) SendCredits(credit int) error {
	if ub.connectedDevice == nil {
		return ErrNotConnected
	}

	creditHex := uint8ToString(uint8(credit))
	c := ub.newCharacteristicHexCommand(commandValueHandle, creditCommand, creditHex)
	_, err := ub.writeAndWait(writeCharacteristicHexCommand(c), false)
	return err
}

// EraseRecorder issues the erase command - which wipes the sensor (use with care)
func (ub *UbloxBluetooth) EraseRecorder() error {
	if ub.connectedDevice == nil {
		return ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, recorderEraseCommand)
	_, err := ub.writeAndWait(writeCharacteristicCommand(c), false)
	return err
}

func (ub *UbloxBluetooth) simpleCommand(cmd []byte) error {
	if ub.connectedDevice == nil {
		return ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, cmd)
	_, err := ub.writeAndWait(writeCharacteristicCommand(c), false)
	return err
}

// RebootRecorder issues the reboot command to the sensor.
func (ub *UbloxBluetooth) RebootRecorder() error {
	return ub.simpleCommand(rebootCommand)
}

// AbortEventLogRead aborts the read
func (ub *UbloxBluetooth) AbortEventLogRead() error {
	return ub.simpleCommand(abortCommand)
}

// WriteMessage writes `msg` string to the device's event log. messageCommand
func (ub *UbloxBluetooth) WriteMessage(msg string) error {
	if ub.connectedDevice == nil {
		return ErrNotConnected
	}

	msgLen := len(msg)
	if msgLen > maxMessageLength {
		msgLen = maxMessageLength
	}

	c := ub.newCharacteristicHexCommand(commandValueHandle, writeConfigCommand, stringToHexString(msg[:msgLen]))
	_, err := ub.writeAndWait(writeCharacteristicHexCommand(c), false)
	return err
}

// EchoCommand sends the `data` string as bytes, and receives something in return.
func (ub *UbloxBluetooth) EchoCommand(data string) (bool, error) {
	if ub.connectedDevice == nil {
		return false, ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, echoCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return false, errors.Wrap(err, "EchoCommand error")
	}
	return ProcessEchoReply(d)
}

// ReadRecorderInfo reads the Recorder information
func (ub *UbloxBluetooth) ReadRecorderInfo() (*RecorderInfoReply, error) {
	if ub.connectedDevice == nil {
		return nil, ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, recorderInfoCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return nil, errors.Wrap(err, "RecorderInfo error")
	}
	return ProcessReadRecorderInfoReply(d)
}

// ReadRecorder downloads the record entries starting from the given sequence.
// Each response is converted to a VehEvent and the function `fn` is invoked with it.
func (ub *UbloxBluetooth) ReadRecorder(sequence uint32, fn func(*VehEvent) error) error {
	commandParameters := fmt.Sprintf("%s%s", uint32ToString(sequence), defaultCreditString)
	err := ub.downloadData(readRecorderCommand, commandParameters, readRecorderOffset, readRecorderReply, func(d []byte) error {
		if d != nil {
			b, err := hex.DecodeString(string(d))
			if err != nil {
				return err
			}

			ve, err := NewRecorderEvent(b)
			if err == nil {
				return fn(ve)
			}
		}
		return nil
	}, func(d []byte) error {
		return nil
	})
	return err
}

func (ub *UbloxBluetooth) ReadSensorEventSlot(sequence uint32) (*VehEvent, error) {
	slot := &VehEvent{}
	commandParameters := fmt.Sprintf("%s%s", uint32ToString(sequence), defaultCreditString)
	err := ub.downloadData(readRecorderCommand, commandParameters, readRecorderOffset, readRecorderReply, func(d []byte) error {
		if d != nil {
			b, err := hex.DecodeString(string(d))
			if err != nil {
				return errors.Wrap(err, "DecodeString error")
			}
			slot, err = NewRecorderEvent(b)
			if err != nil {
				return errors.Wrap(err, "NewRecorderEvent error")
			}

		}
		return nil
	}, func(d []byte) error {
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "downloadData error")
	}
	return slot, nil
}

// QueryRecorderMetaDataCommand gets the
func (ub *UbloxBluetooth) QueryRecorderMetaDataCommand(sequence uint32) (*RecorderMetaDataReply, error) {
	if ub.connectedDevice == nil {
		return nil, ErrNotConnected
	}

	cmd := make([]byte, 5)
	cmd[0] = queryRecorderCommand[0]
	binary.LittleEndian.PutUint32(cmd[1:], uint32(sequence))

	c := ub.newCharacteristicCommand(commandValueHandle, cmd)

	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return nil, errors.Wrap(err, "RecorderInfo error")
	}
	return ProcessQueryRecorderMetaDataReply(d)
}

// ReadSensorEventPool issues the readRecorderDataCommand and handles the onslaught of data thats returned
func (ub *UbloxBluetooth) ReadSensorEventPool(sequence uint32) ([]byte, error) {
	data := []byte{}
	commandParameters := fmt.Sprintf("%s%s", uint32ToString(sequence), defaultCreditString)
	err := ub.downloadData(readRecorderDataCommand, commandParameters, readRecorderDataOffset, readRecorderDataReply, func(d []byte) error {
		if d != nil {
			b, err := hex.DecodeString(string(d))
			if err != nil {
				return err
			}
			data = append(data, b...)
		}
		return nil
	}, func(d []byte) error {
		return nil
	})
	return data, err
}

// GetRSSI returns the RSSI value for the gateway from the connected device
func (ub *UbloxBluetooth) GetRSSI() (*RSSIReply, error) {
	if ub.connectedDevice == nil {
		return nil, ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, rssiCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return nil, errors.Wrapf(err, "GetRSSI error")
	}
	return NewRSSIReply(d)
}

func (ub *UbloxBluetooth) downloadData(command []byte, commandParameters string, lengthOffset int, reply string, dnh func([]byte) error, dih func([]byte) error) error {
	if ub.connectedDevice == nil {
		return ErrNotConnected
	}

	c := ub.newCharacteristicHexCommand(commandValueHandle, command, commandParameters)
	d, err := ub.writeAndWait(writeCharacteristicHexCommand(c), true)
	if err != nil {
		return errors.Wrap(err, "[downloadData] Command error")
	}

	t, err := splitOutResponse(d, reply)
	if err != nil {
		if err == ErrorSensorErrorResponse {
			return err
		}
		return errors.Wrap(err, "[downloadData] processEventsReply error")
	}
	return ub.HandleDataDownload(stringToInt(t[lengthOffset-4:]), reply, dnh, dih)
}

// DfuInit Initialises a DFU session
func (ub *UbloxBluetooth) DfuInit(dp *DfuParams) (uint16, error) {
	if ub.connectedDevice == nil {
		return 0xffff, ErrNotConnected
	}

	dfu := make([]byte, 150)
	dfu[0] = dfuInitCommand[0]
	dfu[1] = byte(dp.ImgFlags)
	dfu[2] = byte(dp.DfuCtx)
	binary.LittleEndian.PutUint16(dfu[3:], dp.MtuSize)
	binary.LittleEndian.PutUint32(dfu[5:], dp.StartingSeqNo)
	copy(dfu[9:], dp.HashSha256[:])
	copy(dfu[41:], dp.Signature[:])
	binary.LittleEndian.PutUint32(dfu[105:], dp.ImgQspiOffset)
	binary.LittleEndian.PutUint32(dfu[109:], dp.ImgLength)
	copy(dfu[113:], dp.ImgVersion[:])
	binary.LittleEndian.PutUint32(dfu[145:], dp.CodeBase)
	dfu[149] = dp.SdVersion

	c := ub.newCharacteristicCommand(commandValueHandle, dfu)
	reply, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return 0xffff, errors.Wrap(err, "DfuInit Command error")
	}

	return NewDfuInitReply(reply)
}

// DfuPacket send a firmware packet
func (ub *UbloxBluetooth) DfuPacket(seqNo uint16, pl []byte) (uint16, error) {
	if ub.connectedDevice == nil {
		return 0xffff, ErrNotConnected
	}

	if len(pl) > DfuPayloadMTU {
		return 0xffff, ErrDfuPayloadTooBig
	}

	cmd := make([]byte, 5)
	cmd[0] = dfuPacketCommand[0]
	binary.LittleEndian.PutUint16(cmd[1:], seqNo)
	binary.LittleEndian.PutUint16(cmd[3:], 0)
	cmd = append(cmd, pl...)

	c := ub.newCharacteristicCommand(commandValueHandle, cmd)
	reply, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return 0xffff, errors.Wrap(err, "DfuPacket Command error")
	}

	return NewDfuPacketReply(reply)
}

// DfuXferDone signals the end of the firmware transfer session
func (ub *UbloxBluetooth) DfuXferDone() error {
	return ub.simpleCommand(dfuXferDoneCommand)
}

// DfuUpgrade inform the sensor to upgrade the firmware that has been sent
func (ub *UbloxBluetooth) DfuUpgrade() error {
	return ub.simpleCommand(dfuUpgradeCommand)
}

// DfuAbort aborts the current upgrade session
func (ub *UbloxBluetooth) DfuAbort() error {
	return ub.simpleCommand(dfuAbortCommand)
}

// ExchangeECDHPublicKeys exchange ECDH public keys
func (ub *UbloxBluetooth) ExchangeECDHPublicKeys(gwPublicKey []byte) ([]byte, error) {
	if ub.connectedDevice == nil {
		return nil, ErrNotConnected
	}
	if len(gwPublicKey) != 64 {
		return nil, fmt.Errorf("ExchangeECDHPublicKeys public key not 64 characters long")
	}
	c := ub.newCharacteristicCommand(commandValueHandle, append(ecdhPublicKeyCommand, gwPublicKey...))
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return nil, errors.Wrapf(err, "ExchangeECDHPublicKeys error")
	}

	return NewECDHPublicKeyReply(d)
}

// GetSemVerVersion request the connected device's SemVer version number
func (ub *UbloxBluetooth) GetSemVerVersion() (string, error) {
	if ub.connectedDevice == nil {
		return "", ErrNotConnected
	}

	c := ub.newCharacteristicCommand(commandValueHandle, getSemVerVersionCommand)
	d, err := ub.writeAndWait(writeCharacteristicCommand(c), true)
	if err != nil {
		return "", errors.Wrapf(err, "GetVersion error")
	}
	return NewSemVerVersionReply(d)
}
