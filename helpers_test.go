package nostrmix_test

import (
	"bufio"
	"errors"
	"os"

	"github.com/coder/websocket"
)

func readFirstLine(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 16<<20)
	if !sc.Scan() {
		return nil, errors.New("empty " + path)
	}
	return sc.Bytes(), nil
}

func asClose(err error, ce *websocket.CloseError) bool { return errors.As(err, ce) }
