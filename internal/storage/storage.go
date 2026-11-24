// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/blake2b"

	"github.com/openfir/openfir/internal/cdc"
)

const (
	EntryTypeFile uint8 = 0x00
	EntryTypeDir  uint8 = 0x01
)

var (
	entryMagic = [4]byte{'O', 'F', 'E', '1'}
	stateMagic = [4]byte{'O', 'F', 'S', '1'}
)

// ============================================================================
// 1. Zero-RTT VirtualDirectoryExtent (Tarless, O(log N) Random Access, 64-FD LRU)
// ============================================================================

type virtualEntry struct {
	absPath     string
	headerBytes []byte
	fileSize    int64
	startOffset int64
	endOffset   int64
}

type VirtualDirectoryExtent struct {
	entries   []virtualEntry
	totalSize int64
	fdCache   *cdc.FDLRUCache
}

func NewVirtualDirectoryExtent(rootDir string) (*VirtualDirectoryExtent, error) {
	rootDir = filepath.Clean(rootDir)
	var entries []virtualEntry
	var curOff int64

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == rootDir {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// Security: never follow symlinks outside tree
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		slashRel := filepath.ToSlash(rel)
		relBytes := []byte(slashRel)
		if len(relBytes) == 0 || len(relBytes) > 65535 {
			return nil
		}

		var eType uint8
		var fSize int64
		if d.IsDir() {
			eType = EntryTypeDir
		} else if info.Mode().IsRegular() {
			eType = EntryTypeFile
			fSize = info.Size()
		} else {
			return nil
		}

		hdr := make([]byte, 19+len(relBytes))
		copy(hdr[0:4], entryMagic[:])
		hdr[4] = eType
		binary.BigEndian.PutUint32(hdr[5:9], uint32(info.Mode().Perm()))
		binary.BigEndian.PutUint64(hdr[9:17], uint64(fSize))
		binary.BigEndian.PutUint16(hdr[17:19], uint16(len(relBytes)))
		copy(hdr[19:], relBytes)

		span := int64(len(hdr)) + fSize
		entries = append(entries, virtualEntry{
			absPath:     path,
			headerBytes: hdr,
			fileSize:    fSize,
			startOffset: curOff,
			endOffset:   curOff + span,
		})
		curOff += span
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &VirtualDirectoryExtent{
		entries:   entries,
		totalSize: curOff,
		fdCache:   cdc.NewFDLRUCache(cdc.DefaultFDLRUCap),
	}, nil
}

func (v *VirtualDirectoryExtent) Size() int64    { return v.totalSize }
func (v *VirtualDirectoryExtent) ItemCount() int { return len(v.entries) }
func (v *VirtualDirectoryExtent) Close() error {
	v.fdCache.Close()
	return nil
}

func (v *VirtualDirectoryExtent) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= v.totalSize {
		return 0, io.EOF
	}
	idx := sort.Search(len(v.entries), func(i int) bool {
		return v.entries[i].endOffset > off
	})

	totalCopied := 0
	curOff := off
	for totalCopied < len(p) && idx < len(v.entries) {
		e := &v.entries[idx]
		relOff := curOff - e.startOffset
		hdrLen := int64(len(e.headerBytes))

		if relOff < hdrLen {
			avail := int(hdrLen - relOff)
			need := len(p) - totalCopied
			if avail > need {
				avail = need
			}
			copy(p[totalCopied:totalCopied+avail], e.headerBytes[relOff:int(relOff)+avail])
			totalCopied += avail
			curOff += int64(avail)
			relOff += int64(avail)
		}

		if totalCopied < len(p) && relOff >= hdrLen {
			fileOff := relOff - hdrLen
			avail := e.fileSize - fileOff
			if avail > 0 {
				need := int64(len(p) - totalCopied)
				toRead := avail
				if toRead > need {
					toRead = need
				}
				n, err := v.fdCache.ReadAt(e.absPath, p[totalCopied:totalCopied+int(toRead)], fileOff)
				totalCopied += n
				curOff += int64(n)
				if n == 0 || (err != nil && err != io.EOF) {
					if err != nil && err != io.EOF {
						return totalCopied, err
					}
					return totalCopied, errors.New("source file truncated during transfer")
				}
			}
		}
		idx++
	}
	if totalCopied < len(p) {
		return totalCopied, io.EOF
	}
	return totalCopied, nil
}

// OpenSourceExtent opens either a single file or a directory as a unified io.ReaderAt + io.Closer.
func OpenSourceExtent(path string) (readerAt io.ReaderAt, closer io.Closer, size int64, isDir bool, itemCount int, err error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, nil, 0, false, 0, err
	}
	if st.IsDir() {
		ext, err := NewVirtualDirectoryExtent(path)
		if err != nil {
			return nil, nil, 0, false, 0, err
		}
		return ext, ext, ext.Size(), true, ext.ItemCount(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, false, 0, err
	}
	return f, f, st.Size(), false, 1, nil
}

// NewExtentReader wraps an io.ReaderAt into a sequential io.Reader for zero-copy Rabin CDC streaming.
func NewExtentReader(r io.ReaderAt, size int64) io.Reader {
	return io.NewSectionReader(r, 0, size)
}

// ============================================================================
// 2. Hardened Safe Directory Bundle Extractor
// ============================================================================

func ValidateSafeName(rawName string) (string, error) {
	if strings.ContainsRune(rawName, 0) {
		return "", errors.New("invalid NUL character in filename")
	}
	base := filepath.Base(filepath.Clean(rawName))
	if base == "" || base == "." || base == ".." || base == "/" || base == "\\" || filepath.VolumeName(base) != "" {
		return "", errors.New("invalid destination filename")
	}
	return base, nil
}

func validateSafeExtractPath(absRoot, rawSlashRel string) (string, error) {
	if strings.ContainsRune(rawSlashRel, 0) || strings.ContainsRune(rawSlashRel, '\\') {
		return "", errors.New("unsafe path characters rejected")
	}
	cleanRel := filepath.Clean(filepath.FromSlash(rawSlashRel))
	if cleanRel == "." || cleanRel == ".." || filepath.IsAbs(cleanRel) || filepath.VolumeName(cleanRel) != "" {
		return "", errors.New("unsafe relative path rejected")
	}
	if strings.HasPrefix(cleanRel, ".."+string(os.PathSeparator)) {
		return "", errors.New("directory traversal rejected")
	}
	dstPath := filepath.Join(absRoot, cleanRel)
	absDst, err := filepath.Abs(dstPath)
	if err != nil {
		return "", err
	}
	relCheck, err := filepath.Rel(absRoot, absDst)
	if err != nil || relCheck == "." || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) {
		return "", errors.New("extracted path escapes target root")
	}
	return absDst, nil
}

func UnpackDirectoryBundle(bundleFile *os.File, bundleSize int64, targetRootDir string) (int, error) {
	if err := os.MkdirAll(targetRootDir, 0755); err != nil {
		return 0, err
	}
	absRoot, err := filepath.Abs(targetRootDir)
	if err != nil {
		return 0, err
	}

	var offset int64
	extracted := 0
	hdrBuf := make([]byte, 19)
	copyBuf := make([]byte, 256*1024)

	for offset < bundleSize {
		if offset+19 > bundleSize {
			return extracted, errors.New("corrupted directory bundle header")
		}
		if n, err := bundleFile.ReadAt(hdrBuf, offset); n != 19 || (err != nil && err != io.EOF) {
			return extracted, errors.New("short read on directory bundle header")
		}
		if hdrBuf[0] != entryMagic[0] || hdrBuf[1] != entryMagic[1] || hdrBuf[2] != entryMagic[2] || hdrBuf[3] != entryMagic[3] {
			return extracted, errors.New("invalid directory bundle magic")
		}
		eType := hdrBuf[4]
		perm := fs.FileMode(binary.BigEndian.Uint32(hdrBuf[5:9])) & 0777
		if perm == 0 {
			perm = 0644
		}
		fSize := int64(binary.BigEndian.Uint64(hdrBuf[9:17]))
		pLen := int(binary.BigEndian.Uint16(hdrBuf[17:19]))
		offset += 19

		if pLen <= 0 || fSize < 0 || offset+int64(pLen)+fSize > bundleSize {
			return extracted, errors.New("corrupted directory bundle bounds")
		}
		pBytes := make([]byte, pLen)
		if n, err := bundleFile.ReadAt(pBytes, offset); n != pLen || (err != nil && err != io.EOF) {
			return extracted, errors.New("short read on directory bundle path")
		}
		offset += int64(pLen)

		dstPath, err := validateSafeExtractPath(absRoot, string(pBytes))
		if err != nil {
			return extracted, err
		}
		if eType == EntryTypeDir {
			if err := os.MkdirAll(dstPath, 0755); err != nil {
				return extracted, err
			}
			extracted++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return extracted, err
		}
		if linfo, lerr := os.Lstat(dstPath); lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
			if rmErr := os.Remove(dstPath); rmErr != nil {
				return extracted, rmErr
			}
		}
		outF, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
		if err != nil {
			return extracted, err
		}
		rem := fSize
		for rem > 0 {
			step := int64(len(copyBuf))
			if rem < step {
				step = rem
			}
			n, rErr := bundleFile.ReadAt(copyBuf[:step], offset)
			if n > 0 {
				if _, wErr := outF.Write(copyBuf[:n]); wErr != nil {
					_ = outF.Close()
					return extracted, wErr
				}
				offset += int64(n)
				rem -= int64(n)
			}
			if n == 0 {
				_ = outF.Close()
				return extracted, io.ErrUnexpectedEOF
			}
			if rErr != nil && rErr != io.EOF {
				_ = outF.Close()
				return extracted, rErr
			}
		}
		_ = outF.Close()
		extracted++
	}
	return extracted, nil
}

// ============================================================================
// 3. Persistent Crash-Resumable Staging (.openfir-part + .openfir-state Journal)
// ============================================================================

// ResumableStaging manages atomic file/directory staging with persistent block-level
// checkpointing so interrupted multi-GB transfers NEVER discard progress across restarts!
type ResumableStaging struct {
	mu           sync.Mutex
	checkpointMu sync.Mutex
	finalPath    string
	stagingPath  string
	statePath    string
	totalSize    int64
	isDir        bool
	file         *os.File

	// Completed blocks indexed by exact (Offset, Length, Hash) persisted in .openfir-state!
	completed map[uint32]cdc.BlockMeta
}

// StagingKey produces a deterministic transfer fingerprint so restarting the exact same file/size
// locates and resumes its existing .openfir-part + .openfir-state files automatically!
func StagingKey(fileName string, totalSize int64, isDir bool) string {
	h, _ := blake2b.New256(nil)
	var b [9]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(totalSize))
	if isDir {
		b[8] = 1
	}
	h.Write(b[:])
	h.Write([]byte(fileName))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func OpenResumableStaging(outDir, safeName string, totalSize int64, isDir bool) (*ResumableStaging, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, err
	}
	key := StagingKey(safeName, totalSize, isDir)
	finalPath := filepath.Join(outDir, safeName)
	stagingPath := filepath.Join(outDir, fmt.Sprintf(".%s.openfir-part-%s", safeName, key))
	statePath := stagingPath + ".openfir-state"

	f, err := os.OpenFile(stagingPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Size() != totalSize {
		if err := f.Truncate(totalSize); err != nil {
			_ = f.Close()
			return nil, err
		}
	}

	rs := &ResumableStaging{
		finalPath:   finalPath,
		stagingPath: stagingPath,
		statePath:   statePath,
		totalSize:   totalSize,
		isDir:       isDir,
		file:        f,
		completed:   make(map[uint32]cdc.BlockMeta),
	}
	rs.loadStateLocked()
	return rs, nil
}

func (rs *ResumableStaging) loadStateLocked() {
	raw, err := os.ReadFile(rs.statePath)
	if err != nil || len(raw) < 16 {
		return
	}
	if raw[0] != stateMagic[0] || raw[1] != stateMagic[1] || raw[2] != stateMagic[2] || raw[3] != stateMagic[3] {
		return
	}
	savedSize := int64(binary.BigEndian.Uint64(raw[4:12]))
	if savedSize != rs.totalSize {
		return
	}
	count := int(binary.BigEndian.Uint32(raw[12:16]))
	const recSize = 4 + 8 + 4 + 32 // 48 bytes per verified block record
	if 16+count*recSize > len(raw) {
		return
	}
	pos := 16
	for i := 0; i < count; i++ {
		idx := binary.BigEndian.Uint32(raw[pos : pos+4])
		off := int64(binary.BigEndian.Uint64(raw[pos+4 : pos+12]))
		ln := binary.BigEndian.Uint32(raw[pos+12 : pos+16])
		var hash [32]byte
		copy(hash[:], raw[pos+16:pos+48])
		pos += recSize
		if off >= 0 && off+int64(ln) <= rs.totalSize {
			rs.completed[idx] = cdc.BlockMeta{
				Index:  idx,
				Offset: off,
				Length: ln,
				Hash:   hash,
			}
		}
	}
}

// SaveCheckpoint atomically flushes the verified block journal to .openfir-state!
func (rs *ResumableStaging) SaveCheckpoint() error {
	rs.checkpointMu.Lock()
	defer rs.checkpointMu.Unlock()

	rs.mu.Lock()
	const recSize = 48
	buf := make([]byte, 16+len(rs.completed)*recSize)
	copy(buf[0:4], stateMagic[:])
	binary.BigEndian.PutUint64(buf[4:12], uint64(rs.totalSize))
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(rs.completed)))
	pos := 16
	for _, m := range rs.completed {
		binary.BigEndian.PutUint32(buf[pos:pos+4], m.Index)
		binary.BigEndian.PutUint64(buf[pos+4:pos+12], uint64(m.Offset))
		binary.BigEndian.PutUint32(buf[pos+12:pos+16], m.Length)
		copy(buf[pos+16:pos+48], m.Hash[:])
		pos += recSize
	}
	rs.mu.Unlock()

	tmp := rs.statePath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, rs.statePath)
}

// HasVerifiedBlock checks whether this exact (Index, Offset, Length, Hash) block was already
// written & verified on disk (supporting instant crash/disconnect resume across restarts!).
func (rs *ResumableStaging) HasVerifiedBlock(meta cdc.BlockMeta) bool {
	rs.mu.Lock()
	existing, ok := rs.completed[meta.Index]
	rs.mu.Unlock()
	if !ok {
		return false
	}
	if existing.Offset != meta.Offset || existing.Length != meta.Length || existing.Hash != meta.Hash {
		return false
	}
	// Cryptographically verify persisted bytes on disk before trusting resume!
	buf := make([]byte, meta.Length)
	n, err := rs.file.ReadAt(buf, meta.Offset)
	if (err != nil && err != io.EOF) || uint32(n) != meta.Length {
		return false
	}
	return cdc.HashBlock(buf) == meta.Hash
}

// WriteVerifiedBlock verifies BLAKE2b-256 hash, writes block to disk at exact Offset, and records it.
func (rs *ResumableStaging) WriteVerifiedBlock(meta cdc.BlockMeta, data []byte) error {
	if uint32(len(data)) != meta.Length || meta.Offset < 0 || meta.Offset+int64(meta.Length) > rs.totalSize {
		return errors.New("block bounds mismatch")
	}
	if cdc.HashBlock(data) != meta.Hash {
		return errors.New("block BLAKE2b-256 verification failed")
	}
	if _, err := rs.file.WriteAt(data, meta.Offset); err != nil {
		return err
	}
	rs.mu.Lock()
	rs.completed[meta.Index] = meta
	rs.mu.Unlock()
	return nil
}

// Commit finalizes the staging file (fsync + unpack if directory OR atomic os.Rename),
// registers blocks into casStore, and cleans up the .openfir-state sidecar!
func (rs *ResumableStaging) Commit(allowOverwrite bool, casStore *cdc.CASStore) (extractedItems int, err error) {
	if err := rs.file.Sync(); err != nil {
		return 0, err
	}
	if casStore != nil {
		casStore.EvictPath(rs.finalPath)
	}
	if rs.isDir {
		if !allowOverwrite {
			if _, sErr := os.Stat(rs.finalPath); sErr == nil {
				return 0, errors.New("destination directory already exists and -overwrite is false")
			}
		}
		cnt, uErr := UnpackDirectoryBundle(rs.file, rs.totalSize, rs.finalPath)
		_ = rs.file.Close()
		rs.file = nil
		if uErr != nil {
			return 0, uErr
		}
		_ = os.Remove(rs.stagingPath)
		_ = os.Remove(rs.statePath)
		if casStore != nil {
			casStore.IndexPath(rs.finalPath)
		}
		return cnt, nil
	}

	_ = rs.file.Close()
	rs.file = nil
	if !allowOverwrite {
		if _, sErr := os.Stat(rs.finalPath); sErr == nil {
			return 0, errors.New("destination file already exists and -overwrite is false")
		}
	} else {
		_ = os.Remove(rs.finalPath)
	}
	if err := os.Rename(rs.stagingPath, rs.finalPath); err != nil {
		return 0, err
	}
	_ = os.Remove(rs.statePath)

	// Register all already-hashed Rabin CDC blocks directly into Global CAS at ZERO extra disk read cost!
	if casStore != nil {
		rs.mu.Lock()
		for _, m := range rs.completed {
			casStore.RegisterBlock(m.Hash, rs.finalPath, m.Offset, m.Length)
		}
		rs.mu.Unlock()
	}
	return 1, nil
}

// PauseAndClose saves the .openfir-state checkpoint and closes the file descriptor WITHOUT deleting
// the partial staging file so the transfer can instantaneously resume later!
func (rs *ResumableStaging) PauseAndClose() {
	_ = rs.SaveCheckpoint()
	rs.mu.Lock()
	f := rs.file
	rs.file = nil
	rs.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
}
