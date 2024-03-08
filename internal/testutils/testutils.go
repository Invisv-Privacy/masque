package testutils

import (
	"log"
	"path"
	"path/filepath"
	"runtime"
)

func RootDir() string {
	_, b, _, _ := runtime.Caller(0)
	log.Printf("b: %v", b)
	d := path.Join(path.Dir(path.Dir(b)))
	return filepath.Dir(d)
}
