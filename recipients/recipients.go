package recipients

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const FileName = ".cryptree_recipients"

func Resolve(path string) ([]string, error) {
	dir := filepath.Dir(path)
	return ResolveDir(dir)
}

func ResolveDir(dir string) ([]string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for {
		p := filepath.Join(dir, FileName)
		if _, err := os.Stat(p); err == nil {
			return Parse(p)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, fmt.Errorf("no %s found", FileName)
		}
		dir = parent
	}
}

func Parse(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var keys []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}
	return keys, s.Err()
}

func Append(path string, pubkey string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	prefix := ""
	if info.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			prefix = "\n"
		}
	}
	if _, err := fmt.Fprintf(f, "%s%s\n", prefix, pubkey); err != nil {
		return err
	}
	return f.Close()
}
