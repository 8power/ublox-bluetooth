package serial

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

var PathNotFound = fmt.Errorf("Port not found")
var FormatError = fmt.Errorf("Format Error")

type BtdSerial struct {
	SerialPort string
	PortNo     int
}

// GetFTDIDevPaths gets the current dev paths for all FTDI connected devices,
// This is based on `/proc/tty/driver/usbserial` containing info in the format of:
// 0: module:ftdi_sio name:"FTDI USB Serial Device" vendor:0403 product:6015 num_ports:1 port:0 path:usb-0000:00:14.0-1.2.2
// or
// 1: module:ftdi_sio name:"FTDI USB Serial Device" vendor:0403 product:6015 num_ports:1 port:0 path:usb-0000:00:14.0-1.2
func GetFTDIDevPaths() ([]*BtdSerial, error) {
	serialPorts := make([]*BtdSerial, 0)
	usbserial, err := os.Open("/proc/tty/driver/usbserial")
	if err != nil {
		return nil, errors.Wrap(err, "error opening serial driver list")
	}
	defer usbserial.Close()

	scanner := bufio.NewScanner(usbserial)

	for scanner.Scan() {
		tokens := strings.Split(scanner.Text(), " ")
		index := strings.Split(tokens[0], ":")
		module := strings.Split(tokens[1], ":")
		if module[1] == "ftdi_sio" && len(tokens) > 7 {
			vendor := strings.Split(tokens[6], ":")
			product := strings.Split(tokens[7], ":")
			if vendor[1] == "0403" && product[1] == "6015" {
				portNo, err := strconv.Atoi(index[0])
				if err == nil {
					serialPorts = append(serialPorts, &BtdSerial{
						SerialPort: fmt.Sprintf("/dev/ttyUSB%s", index[0]),
						PortNo:     portNo,
					})
				} else {
					return nil, errors.Wrap(err, "Error parsing serial driver record")
				}
			}
		}
	}

	if len(serialPorts) == 0 {
		return nil, PathNotFound
	}
	return serialPorts, nil
}
