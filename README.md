# Ublox-Bluetooth

This implements a small subset of the AT commands defined in the [u-blox Short Range Modules](https://www.u-blox.com/sites/default/files/u-blox-SHO_ATCommands_%28UBX-14044127%29.pdf) documents

Its a Linux only implementation.

In order to run tests as a User you will need to ensure that the User ownership is correct: `sudo chown $USER:$USER -R /proc/tty/driver`

## Serial Directory

The `serial` directory contains the code to open, configure, read, and write data to/from the serial port.

* `OpenSerialPort` automatically discovers and configures the Ublox serial port.
* `SetVerbose` when set to `true`, logs all serial traffic to console.
* `Write` writes the passed byte array to the serial port.
* `ScanPort` handles the read functionality and passes the incoming data to one of the three channels specified.
* `Flush`  ensures unwritten bytes are pushed through the serial port.
* `ResetViaDTR` provides a method of reseting the Ublox serial port and Nina Module.
* `Close` shuts the underlying file descriptor.

## Main Directory

The main Ublox functionality resides in the main directory. The functionality of which is best described by the test files:

### config_test.go

* `TestGetVersion` configures the bluetooth environment, connects to the sensor defined by `TestDeviceMAC` (which needs to be defined), and then gets the Sensor's software, hardware and release version information.
* `TestConfiguration` configures the bluetooth environment, connects to the sensor defined by `TestDeviceMAC` (which needs to be defined), reads the sensor's config, makes a change to the config and writes it back to the sensor.

### restart_test.go

Exercises the various restart methods supported by the library.

* `TestResetWatchdog` resets the Ublox watchdog configuration.
* `TestSetWatchdog` sets the watchdog configuration with the project's inactivityTimeoutValue (6000ms) and resetValue (1)
* `TestRestartViaDTR` demonstrates the board reset command, which is issued by changing the DTR lines
* `TestRestart` demonstrates `RebootUblox` which resets the SoC by issuing the `powerOff` command. 