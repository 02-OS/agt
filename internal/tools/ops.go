package tools

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

const maxReadBytes = 1 << 20

// Search returns literal matches as path:line:text, capped at 50 hits.
func Search(root, query string) (string, error) {
	return SearchFiltered(root, query, "", "")
}

// SearchFiltered searches root (optionally scoped to relPath and glob) for
// literal query matches, or matching file paths when query is empty and glob is set.
func SearchFiltered(root, query, relPath, glob string) (string, error) {
	if strings.TrimSpace(query) == "" && strings.TrimSpace(glob) == "" {
		return "", fmt.Errorf("empty query")
	}
	walkRoot := root
	if strings.TrimSpace(relPath) != "" && strings.TrimSpace(relPath) != "." {
		clean, err := SafeRel(relPath)
		if err != nil {
			return "", err
		}
		if SecretRel(clean) {
			return "", fmt.Errorf("secret paths are not available to the agent")
		}
		full, err := Within(root, clean)
		if err != nil {
			return "", err
		}
		walkRoot = full
	}
	cleanGlob := strings.ReplaceAll(strings.TrimSpace(glob), "\\", "/")
	if cleanGlob != "" {
		if strings.ContainsAny(cleanGlob, "\x00:") || strings.HasPrefix(cleanGlob, "/") || strings.Contains(cleanGlob, "..") {
			return "", fmt.Errorf("invalid glob")
		}
		if _, err := path.Match(strings.TrimPrefix(cleanGlob, "**/"), "sample"); err != nil {
			return "", fmt.Errorf("invalid glob: %w", err)
		}
	}

	var b strings.Builder
	n := 0
	scanBuf := make([]byte, 64*1024)
	var sniff [512]byte

	searchOne := func(fullPath string, d fs.DirEntry, info fs.FileInfo) error {
		if info.Size() > maxReadBytes {
			return nil
		}
		rel, err := filepath.Rel(root, fullPath)
		if err != nil {
			return err
		}
		slashRel := filepath.ToSlash(rel)
		if SecretRel(slashRel) {
			return nil
		}
		if cleanGlob != "" && !matchGlob(slashRel, filepath.Base(slashRel), cleanGlob) {
			return nil
		}
		if query == "" {
			fmt.Fprintf(&b, "%s\n", rel)
			n++
			if n >= 50 {
				return fs.SkipAll
			}
			return nil
		}
		f, err := os.Open(fullPath)
		if err != nil {
			return err
		}
		defer f.Close()
		sn, err := io.ReadFull(f, sniff[:])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if bytes.IndexByte(sniff[:sn], 0) >= 0 {
			return nil
		}
		sc := bufio.NewScanner(io.MultiReader(bytes.NewReader(sniff[:sn]), f))
		sc.Buffer(scanBuf, maxReadBytes)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			if strings.Contains(line, query) {
				fmt.Fprintf(&b, "%s:%d:%s\n", rel, lineNo, clip(line, 200))
				n++
				if n >= 50 {
					return fs.SkipAll
				}
			}
		}
		return sc.Err()
	}

	walkInfo, err := os.Lstat(walkRoot)
	if err != nil {
		return "", err
	}
	if walkInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to search a symlink")
	}
	if !walkInfo.IsDir() {
		if walkInfo.Mode().IsRegular() && !SecretFile(walkInfo.Name()) {
			if err := searchOne(walkRoot, nil, walkInfo); err != nil && err != fs.SkipAll {
				return "", err
			}
		}
	} else {
		err = filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if name != "." && (SkipDir(name) || SecretDir(name)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || SecretFile(name) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return searchOne(p, d, info)
		})
		if err != nil {
			return "", err
		}
	}
	if b.Len() == 0 {
		return "(no matches)\n", nil
	}
	return b.String(), nil
}

func matchGlob(slashRel, base, pattern string) bool {
	if strings.HasPrefix(pattern, "**/") {
		sub := strings.TrimPrefix(pattern, "**/")
		if ok, _ := path.Match(sub, base); ok {
			return true
		}
		if ok, _ := path.Match(sub, slashRel); ok {
			return true
		}
		return false
	}
	if strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, slashRel)
		return ok
	}
	ok, _ := path.Match(pattern, base)
	return ok
}

// ReadRange returns 1-based inclusive lines.
func ReadRange(root, rel string, start, end int) (string, error) {
	clean, err := SafeRel(rel)
	if err != nil {
		return "", err
	}
	if SecretRel(clean) {
		return "", fmt.Errorf("secret paths are not available to the agent")
	}
	full, err := Within(root, clean)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	if len(data) > maxReadBytes {
		return "", fmt.Errorf("file exceeds read limit")
	}
	lines := strings.Split(string(data), "\n")
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > len(lines) {
		return "", fmt.Errorf("start line past end of file")
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%d\t%s\n", i, lines[i-1])
	}
	return b.String(), nil
}

type patchRecord struct {
	old  string
	new  string
	hash string
}

var (
	appliedMu      sync.Mutex
	appliedPatches = map[string]patchRecord{}
)

func recordAppliedPatch(full, old, new, hash string) {
	appliedMu.Lock()
	defer appliedMu.Unlock()
	if len(appliedPatches) >= 4096 {
		appliedPatches = map[string]patchRecord{}
	}
	appliedPatches[full] = patchRecord{old: old, new: new, hash: hash}
}

func wasPatchApplied(root, clean, full, old, new string, data []byte) bool {
	if old == new {
		return false
	}
	cur := string(data)
	sum := SHA256(data)
	appliedMu.Lock()
	rec, ok := appliedPatches[full]
	appliedMu.Unlock()
	if ok && rec.old == old && rec.new == new && rec.hash == sum {
		return true
	}
	basePath := filepath.Join(filepath.Dir(root), "base", clean)
	baseData, baseInfo, err := readRegular(basePath)
	if err != nil || baseData == nil || (baseInfo != nil && baseInfo.IsDir()) {
		return false
	}
	baseCur := string(baseData)
	if strings.Count(baseCur, old) != 1 {
		return false
	}
	if strings.Replace(baseCur, old, new, 1) == cur {
		return true
	}
	return strings.Count(cur, new) == strings.Count(baseCur, new)+1 && !strings.Contains(cur, old)
}

// Patch replaces old with new exactly once. A second call with the same
// arguments reports already applied and does not write.
func Patch(root, rel, old, new string) (string, error) {
	if strings.Contains(new, "\x00") {
		return "", fmt.Errorf("content must be text")
	}
	clean, full, err := editable(root, rel)
	if err != nil {
		return "", err
	}
	data, info, err := readRegular(full)
	if err != nil {
		return "", err
	}
	if info != nil && info.IsDir() {
		return "", fmt.Errorf("refusing to edit a directory")
	}
	if data == nil {
		return "", os.ErrNotExist
	}
	cur := string(data)
	if wasPatchApplied(root, clean, full, old, new, data) {
		return "already applied", nil
	}
	if !strings.Contains(cur, old) {
		return "", fmt.Errorf("old text not found")
	}
	if strings.Count(cur, old) != 1 {
		return "", fmt.Errorf("old text is not unique")
	}
	updated := strings.Replace(cur, old, new, 1)
	if len(updated) > MaxWriteBytes {
		return "", fmt.Errorf("content must be under 200KB")
	}
	perm := info.Mode().Perm()
	if perm == 0 {
		perm = 0o644
	}
	updatedBytes := []byte(updated)
	if err := atomicWrite(full, updatedBytes, perm); err != nil {
		return "", err
	}
	recordAppliedPatch(full, old, new, SHA256(updatedBytes))
	return "patched", nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// repoLabel is the repository-relative unified-diff path. Separators are
// forward slashes on every OS, including a Windows Rel result.
func repoLabel(rel string) string {
	return strings.ReplaceAll(filepath.ToSlash(rel), "\\", "/")
}
