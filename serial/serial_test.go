package serial

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestSerial(t *testing.T) {
	timeout := 10 * time.Second
	readChannel := make(chan []byte)
	edmChannel := make(chan []byte)
	errorChannel := make(chan error)
	sp, err := OpenSerialPort("/dev/ttyUSB0", timeout)
	if err != nil {
		t.Fatalf("Open Port Error %v\n", err)
	}
	defer func() {
		fmt.Println("Closing serial port")
		err = sp.Close()
		if err != nil {
			t.Fatalf("Close error %v\n", err)
		}
	}()

	sp.Flush()

	err = sp.ResetViaDTR()
	if err != nil {
		t.Fatalf("ResetViaDTR error %v\n", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	go sp.ScanPort(ctx, readChannel, edmChannel, errorChannel)
	go func() {
		for {
			select {
			case r := <-readChannel:
				fmt.Printf("r: %s\n", r)
			case e := <-edmChannel:
				fmt.Printf("e: %s\n", e)
			case err := <-errorChannel:
				fmt.Printf("err: %v\n", err)
			case <-ctx.Done():
				fmt.Println("Done")
				return
			}
		}
	}()

	time.Sleep(timeout)
	cancel()
}
