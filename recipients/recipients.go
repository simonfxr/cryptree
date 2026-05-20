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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", pubkey)
	return err
}
