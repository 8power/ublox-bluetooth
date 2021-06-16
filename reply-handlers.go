package ubloxbluetooth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

const unlockReply = "00"
const unlockSuccess = "0000"
const statusOk = "00"
const statusPending = "01"
const statusError = "E0"
const versionReply = "01"
const infoReply = "02"
const readConfigReply = "03"
const writeConfigReply = "04"
const readSerialNumberReply = "05"
const setTimeReply = "07"
const echoReply = "0B"
const readRecorderInfoReply = "20"
const readRecorderReply = "21"
const queryRecorderMetaDataReply = "22"
const readRecorderDataReply = "23"
const rssiReply = "24"
const dfuInitReply = "27"
const dfuPacketReply = "28"
const exchangeECDHPublicKeyReply = "2D"
const semVerVersionReply = "2E"

func isIndicationResponseValid(sa []string) bool {
	return sa[0] == "0" && sa[1] == "13"
}

func isNotificationResponseValid(nr [][]byte) bool {
	return nr[0][0] == 48 && nr[1][0] == 49 && nr[1][1] == 54
}

var (
	// ErrorIncorrectResponse - when the response is incorrect for what was sent
	ErrorIncorrectResponse = fmt.Errorf("incorrect response")
	// ErrorUnknownResponse - when there has been a response but its format is unknown
	ErrorUnknownResponse = fmt.Errorf("unknown response")
	// ErrorInvalidResponse - when the format of the response is invalid
	ErrorInvalidResponse = fmt.Errorf("invalid response")
	// ErrorSensorErrorResponse - when the Sensor returns an Error in response to a request
	ErrorSensorErrorResponse = fmt.Errorf("sensor error")
	// ErrorUnexpectedResponse is a type of error that may not be catastrophic - just unexpected
	ErrorUnexpectedResponse = fmt.Errorf("UnexpectedResponse")
	// ErrorTruncatedResponse is a type of error that may not be catastrophic - just unexpected
	ErrorTruncatedResponse = fmt.Errorf("TruncatedResponse")
)

func splitOutResponse(d []byte, command string) (string, error) {
	b := bytes.Split(d, gattIndicationResponse)
	if len(b) < 2 {
		return "", ErrorIncorrectResponse
	}
	tokens := strings.Split(string(b[1]), ",")
	if len(tokens) < 3 {
		return "", ErrorUnknownResponse
	}
	if isIndicationResponseValid(tokens) {
		status := tokens[2][2:4]
		if tokens[2][0:2] == command {
			if status == statusOk || status == statusPending {
				return tokens[2], nil
			}
			if status == statusError {
				return "", ErrorSensorErrorResponse
			}
		}
	}
	return "", ErrorInvalidResponse
}

func splitOutNotification(d []byte, command string) ([]byte, error) {
	b := bytes.Split(d, gattNotificationResponse)
	if len(b) < 2 {
		return nil, ErrorIncorrectResponse
	}
	tokens := bytes.Split(b[1], comma)
	if len(tokens) < 3 {
		return nil, ErrorUnknownResponse
	}
	if isNotificationResponseValid(tokens) {
		return tokens[2], nil
	}
	return nil, ErrorInvalidResponse
}

func stringToHexString(s string) string {
	b, _ := hex.DecodeString(s)
	return string(b)
}

func stringToInt(s string) int {
	b, _ := hex.DecodeString(s)
	switch len(b) {
	case 1:
		return int(b[0])
	case 2:
		return int(binary.LittleEndian.Uint16(b))
	case 4:
		return int(binary.LittleEndian.Uint32(b))
	}
	return 0
}

func stringToFloat32(s string) float32 {
	b, _ := hex.DecodeString(s)
	intVal := binary.LittleEndian.Uint32(b)
	return math.Float32frombits(intVal)
}

func uint8ToString(i uint8) string {
	b := make([]byte, 1)
	b[0] = i
	return hex.EncodeToString(b)
}

func uint16ToString(i uint16) string {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return hex.EncodeToString(b)
}

func uint32ToString(i uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return hex.EncodeToString(b)
}

// ProcessConnectDeviceSPSReply takes the passed string and attempts to parse it for its peerHandle
func ProcessConnectDeviceSPSReply(d string) (int, error) {
	b := strings.Split(d, connectPeerResponseString)
	if len(b) < 2 {
		return -1, fmt.Errorf("[ProcessConnectDeviceSPSReply] could not parse response (%s)", d)
	}

	handle, err := strconv.Atoi(b[1])
	if err != nil {
		return -1, errors.Wrapf(err, "[ProcessConnectDeviceSPSReply] error extracting Handle value (%s)", d)
	}
	return handle, nil
}

// ProcessPeerDisconnectedReply takes the passed string, pulls out the handle and checks that it matches the peerHandle
func ProcessPeerDisconnectedReply(peerHandle int, d string) error {
	b := strings.Split(d, disconnectPeerResponseString)
	if len(b) < 2 {
		return fmt.Errorf("[ProcessPeerDisconnectedReply] could not parse response (%s)", d)
	}

	handle, err := strconv.Atoi(b[1])
	if err != nil {
		return errors.Wrapf(err, "[ProcessPeerDisconnectedReply] error extracting Handle value (%s)", d)
	}

	if handle != peerHandle {
		return fmt.Errorf("[ProcessPeerDisconnectedReply] returned handle does not match required (wanted: %d got %d)", peerHandle, handle)
	}
	return nil
}

// ByteArray turns the `ConfigReply` to hex bytes
func (cr *ConfigReply) ByteArray() string {
	a := fmt.Sprintf("%s%s%s%s%s%s",
		uint16ToString(uint16(cr.AdvertisingInterval)),
		uint16ToString(uint16(cr.SampleTime)),
		uint16ToString(uint16(cr.State)),
		uint16ToString(uint16(cr.AccelSettings)),
		uint16ToString(uint16(cr.SpareOne)),
		uint16ToString(uint16(cr.TemperatureOffset)))
	return a
}

// ProcessUnlockReply returns true or false flag for unlock - or an error
func ProcessUnlockReply(d []byte) (bool, error) {
	t, err := splitOutResponse(d, unlockReply)
	if err != nil {
		return false, err
	}
	return (t == unlockSuccess), nil
}

// ProcessRS232SettingsReply processes the passed bytes for the RS232 settings
func ProcessRS232SettingsReply(d []byte) (*RS232SettingsReply, error) {
	b := bytes.Split(d, rs232SettingsResponse)
	if len(b) < 2 {
		return nil, ErrorIncorrectResponse
	}
	return NewRS232SettingsReply(string(b[1]))
}

// ProcessDiscoveryReply returns an array of DiscoveryReplys and a error
func ProcessDiscoveryReply(d []byte) (*DiscoveryReply, error) {
	b := bytes.Split(d, discoveryResponse)
	if len(b) < 1 {
		return nil, ErrorUnexpectedResponse
	}
	return NewDiscoveryReply(string(b[1]))
}

// ProcessDisconnectReply checks the passed bytes for a correct disconnect.
func ProcessDisconnectReply(d []byte) (bool, error) {
	b := bytes.Split(d, disconnectResponse)
	if len(b) < 2 {
		return false, fmt.Errorf("disconnect error %q", d)
	}
	return b[1][0] == '0', nil
}

// ProcessEchoReply checks the passed bytes for an echo response.
func ProcessEchoReply(d []byte) (bool, error) {
	_, err := splitOutResponse(d, echoReply)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ProcessReadRecorderInfoReply - breaks down the response to extract RecorderInfo
func ProcessReadRecorderInfoReply(d []byte) (*RecorderInfoReply, error) {
	b, err := splitOutResponse(d, readRecorderInfoReply)
	if err != nil {
		return nil, err
	}
	return NewRecorderInfoReply(b), nil
}

// ProcessQueryRecorderMetaDataReply - a
func ProcessQueryRecorderMetaDataReply(d []byte) (*RecorderMetaDataReply, error) {
	t, err := splitOutResponse(d, queryRecorderMetaDataReply)
	if err != nil {
		return nil, err
	}
	return NewRecorderMetaDataReply(t), nil
}

// ProcessReadRecorderDataReply - b
func ProcessReadRecorderDataReply(d []byte) (string, error) {
	t, err := splitOutResponse(d, readRecorderDataReply)
	if err != nil {
		return "nil", err
	}
	return t, fmt.Errorf("NOT IMPLEMENTED")
}

// ProcessRSSIReply - picks the data from the response in +UBTRSS:<rssi>
func ProcessRSSIReply(d []byte) (string, error) {
	b := bytes.Split(d, getRSSIResponse)
	if len(b) < 2 {
		return "??", fmt.Errorf("get RSSI error %q", d)
	}
	return string(b[1]), nil
}
