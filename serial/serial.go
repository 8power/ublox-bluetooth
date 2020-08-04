package serial

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var verbose = false
var newlineBytes = []byte{'\r', '\n'}

// SetVerbose sets the logging level
func SetVerbose(v bool) {
	verbose = v
}

func showOutMsg(b []byte) {
	if verbose {
		l := len(b) - 2
		fmt.Printf("-> %s\n", b[5:l])
	}
}

func showInMsg(b []byte) {
	if verbose {
		l := len(b) - 3
		if l > 7 {
			fmt.Printf("<- %s\n", b[7:l])
		} else {
			fmt.Printf("<- %+q\n", b)
		}
	}
}

// SerialPort holds the file and file descriptor for the serial port
type SerialPort struct {
	file             *os.File
	fd               uintptr
	extendedDataMode bool
	contineScanning  bool
	isOpen           bool
	byteBuf          []byte
}

// BaudRate is a type used for enumerating the permissible rates in our system.
type BaudRate uint32

const (
	// Default baud is 115k
	Default BaudRate = unix.B115200
	// HighSpeed baud is 1m
	HighSpeed BaudRate = unix.B1000000
)

// OpenSerialPort opens the Ublox device with a timeout value
func OpenSerialPort(readTimeout time.Duration) (p *SerialPort, err error) {
	devPath, err := GetFTDIDevPath()
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(devPath, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0666)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil && f != nil {
			fmt.Printf("[OpenSerialPort] ERROR: %v\n", err)
			f.Close()
		}
	}()

	fd := f.Fd()

	unix.SetNonblock(int(fd), false)
	if err != nil {
		return nil, fmt.Errorf("[OpenSerialPort] set non block error: %v", err)
	}

	sp := &SerialPort{
		file:             f,
		fd:               fd,
		extendedDataMode: true,
		contineScanning:  true,
		isOpen:           true,
		byteBuf:          make([]byte, 1),
	}

	sp.SetBaudRate(HighSpeed, readTimeout)
	return sp, nil
}

// SetEDMFlag is set when we leave AT mode.
func (sp *SerialPort) SetEDMFlag(flag bool) {
	sp.extendedDataMode = flag
}

// SetBaudRate sets the serialport's speed to the passed value
func (sp *SerialPort) SetBaudRate(baudrate BaudRate, readTimeout time.Duration) error {
	br := uint32(baudrate)
	t := unix.Termios{
		Iflag:  unix.IGNPAR,
		Cflag:  unix.CREAD | unix.CLOCAL | unix.IGNCR | br | unix.CS8 | unix.CRTSCTS,
		Ispeed: br,
		Ospeed: br,
	}

	t.Cc[unix.VMIN] = uint8(0x00)
	t.Cc[unix.VTIME] = uint8(readTimeout.Nanoseconds() / 1e6 / 100)

	_, _, errno := unix.Syscall6(
		unix.SYS_IOCTL,
		uintptr(sp.fd),
		uintptr(unix.TCSETS),
		uintptr(unsafe.Pointer(&t)),
		0,
		0,
		0,
	)

	if errno != 0 {
		return fmt.Errorf("[OpenPort] ioctl error: %d", errno)
	}
	return nil
}

// Write writes the passed byte array to the serial port
func (sp *SerialPort) Write(b []byte) error {
	showOutMsg(b)
	_, err := sp.file.Write(b)
	return err
}

func (sp *SerialPort) read() (byte, error) {
	_, err := sp.file.Read(sp.byteBuf)
	b := sp.byteBuf[0]
	return b, err
}

const EDMStartByte = byte(0xAA)
const EDMStopByte = byte(0x55)
const EDMPayloadOverhead = 4
const EDMHeaderSize = 3

func (sp *SerialPort) StopScanning() {
	sp.contineScanning = false
}

// ScanPort reads a complete line from the serial port and sends the bytes
// to the passed channel
func (sp *SerialPort) ScanPort(dataChan chan []byte, edmChan chan []byte, errChan chan error) {
	defer func() {
		if err := recover(); err != nil {
			if fmt.Sprintf("%v", err) == "send on closed channel" {
				// Should be enough to avoid a crash/stack trace on shutdown
				fmt.Printf("[UbScanPort] Caught Panic: %v", err)
			} else {
				// Other issue, rethrow the panic
				panic(err)
			}
		}
	}()

	sp.contineScanning = true
	line := []byte{}
	lineLen := 0
	expectedLength := -1
	edmStartReceived := false

	for sp.contineScanning == true {
		b, err := sp.read()
		if err != nil {
			if err == io.EOF { // ignore EOFs we're going to get them all the time.
				continue
			} else {
				if sp.isOpen {
					errChan <- errors.Wrap(err, "serial read error")
				} else {
					fmt.Printf("[ScanPort] Read error %v\n", err)
				}
				break
			}
		}

		if sp.extendedDataMode {
			if !edmStartReceived {
				if b == EDMStartByte {
					edmStartReceived = true
				}
			}
			if edmStartReceived {
				line = append(line, b)
				lineLen = len(line)

				if expectedLength == -1 && lineLen == 3 {
					expectedLength = int(binary.BigEndian.Uint16(line[1:3])) + EDMPayloadOverhead
				} else if lineLen == expectedLength {
					if line[expectedLength-1] == EDMStopByte {
						showInMsg(line)
						edmChan <- line[EDMHeaderSize:expectedLength]
						line = []byte{}
						expectedLength = -1
						edmStartReceived = false
					} else {
						errChan <- fmt.Errorf("EDM errof Payload length exceeded (Length: %d %x)", expectedLength, line)
						line = []byte{}
						expectedLength = -1
						edmStartReceived = false
					}
				}
			}
		} else {
			line = append(line, b)
			lineLen = len(line)
			if bytes.HasSuffix(line, newlineBytes) {
				if lineLen > 2 {
					showInMsg(line)
					dataChan <- line
				}
				line = []byte{}
			}
		}
	}
	fmt.Print("[ScanPort] CATASTROPHIC ERROR")
}

// Ioctl sends
func (sp *SerialPort) ioctl(command int, data int) error {
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sp.fd),
		uintptr(command),
		uintptr(unsafe.Pointer(&data)),
	)
	if errno != 0 {
		return fmt.Errorf("[Ioctl] error: %d", errno)
	}
	return nil
}

// Flush ensures unwritten bytes are pushed through the serial port.
func (sp *SerialPort) Flush() error {
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sp.fd),
		uintptr(0x540B),
		uintptr(unix.TCIOFLUSH),
	)

	if errno != 0 {
		return fmt.Errorf("[Flush] ioctl error: %d", errno)
	}
	return nil
}

var defaultDTRPause = 10 * time.Millisecond

func (sp *SerialPort) setDTR() error {
	err := sp.ioctl(unix.TIOCMBIS, unix.TIOCM_DTR)
	if err != nil {
		return fmt.Errorf("[ToggleDTR] DTR set error: %d", err)
	}
	time.Sleep(defaultDTRPause)
	return nil
}

func (sp *SerialPort) clearDTR() error {
	err := sp.ioctl(unix.TIOCMBIC, unix.TIOCM_DTR)
	if err != nil {
		return fmt.Errorf("[ToggleDTR] DTR clear error: %d", err)
	}
	time.Sleep(defaultDTRPause)
	return nil
}

// ResetViaDTR sends the DTR line low and then takes it high
// if the board has been setup with AT&D4 this will cause a reset.
func (sp *SerialPort) ResetViaDTR() error {
	err := sp.clearDTR()
	if err != nil {
		return err
	}

	err = sp.setDTR()
	if err != nil {
		return err
	}

	return nil
}

// Close closes the file
func (sp *SerialPort) Close() (err error) {
	err = sp.file.Close()
	sp.isOpen = false
	return err
}
