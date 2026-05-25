package storecrypt

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/codec"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/crypt"
	"github.com/pgrwl/pgrwl/internal/opt/shared/streamcrypt/pipe"
)

// CodecPair groups a compressor and its matching decompressor.
type CodecPair struct {
	Compressor   codec.Compressor
	Decompressor codec.Decompressor
}

// Algorithms are where you plug in concrete implementations.
// The variants (plain, .gz, .zst, .gz.aes, .zst.aes, .aes) are
// defined statically in this file.
type Algorithms struct {
	Gzip *CodecPair    // nil if gzip is not configured
	Zstd *CodecPair    // nil if zstd is not configured
	AES  crypt.Crypter // nil if AES is not configured
}

// VariadicStorage is a storage wrapper that:
//
//   - Writes objects using a single configured extension (writeExt).
//   - Reads objects by trying all known variants (extensions) for a
//     given base path and decoding based solely on the found extension.
//
// Callers always work with *logical* names (no transform extensions),
// e.g. "000000010000000000000001".
type VariadicStorage struct {
	Backend  Storage
	alg      Algorithms
	writeExt string // "", ".gz", ".zst", ".gz.aes", ".zst.aes", ".aes"
}

var _ Storage = (*VariadicStorage)(nil)

// NewVariadicStorage creates a new VariadicStorage. writeExt is the
// extension used for *new writes*. It must be one of the supported
// variants for the provided algorithms:
//
//	""         -> plain
//	".gz"      -> gzip
//	".zst"     -> zstd
//	".gz.aes"  -> gzip + AES
//	".zst.aes" -> zstd + AES
func NewVariadicStorage(backend Storage, alg Algorithms, writeExt string) (*VariadicStorage, error) {
	vs := &VariadicStorage{
		Backend:  backend,
		alg:      alg,
		writeExt: writeExt,
	}
	if !vs.isSupportedWriteExt(writeExt) {
		return nil, errors.New("writeExt not supported by provided algorithms")
	}
	return vs, nil
}

// isSupportedWriteExt validates that the chosen writeExt is compatible
// with the configured algorithms.
func (vs *VariadicStorage) isSupportedWriteExt(ext string) bool {
	switch ext {
	case "":
		return true
	case ".gz":
		return vs.alg.Gzip != nil
	case ".zst":
		return vs.alg.Zstd != nil
	case ".gz.aes":
		return vs.alg.Gzip != nil && vs.alg.AES != nil
	case ".zst.aes":
		return vs.alg.Zstd != nil && vs.alg.AES != nil
	case ".aes": // <-- NEW: AES-only is allowed if we have AES
		return vs.alg.AES != nil
	default:
		return false
	}
}

// supportedExts returns the list of extensions this storage knows about,
// in priority order for lookup. You can tweak this order if needed.
func (vs *VariadicStorage) supportedExts() []string {
	var exts []string

	// Prefer more "advanced" variants first.
	if vs.alg.Gzip != nil && vs.alg.AES != nil {
		exts = append(exts, ".gz.aes")
	}
	if vs.alg.Zstd != nil && vs.alg.AES != nil {
		exts = append(exts, ".zst.aes")
	}
	if vs.alg.Gzip != nil {
		exts = append(exts, ".gz")
	}
	if vs.alg.Zstd != nil {
		exts = append(exts, ".zst")
	}
	if vs.alg.AES != nil {
		exts = append(exts, ".aes")
	}
	// plain always last
	exts = append(exts, "")

	return exts
}

// transforms represents the transforms determined purely from a full
// stored name (including its extension).
type transforms struct {
	compressor   codec.Compressor
	decompressor codec.Decompressor
	crypter      crypt.Crypter
}

// transformsFromName inspects the name's extension chain and decides
// which compressor/decompressor/crypter to use, based solely on those
// suffixes and the configured Algorithms.
//
// The logic is:
//
//	[".gz" | ".zst"] [".aes"]?
//
// Currently ".aes" is only used in combination with compression, but
// this can be expanded if needed.
func (vs *VariadicStorage) transformsFromName(name string) transforms {
	t := transforms{}

	// Handle AES as the outermost suffix if configured.
	if vs.alg.AES != nil && strings.HasSuffix(name, ".aes") {
		t.crypter = vs.alg.AES
		name = strings.TrimSuffix(name, ".aes")
	}

	// Compression suffix.
	if vs.alg.Gzip != nil && strings.HasSuffix(name, ".gz") {
		t.compressor = vs.alg.Gzip.Compressor
		t.decompressor = vs.alg.Gzip.Decompressor
		return t
	}

	if vs.alg.Zstd != nil && strings.HasSuffix(name, ".zst") {
		t.compressor = vs.alg.Zstd.Compressor
		t.decompressor = vs.alg.Zstd.Decompressor
		return t
	}

	// No known compression suffix: plain (maybe AES only in future).
	return t
}

// encodePath is used for Put/Delete/DeleteBulk to map a logical
// name to the stored object key using the configured writeExt.
func (vs *VariadicStorage) encodePath(base string) string {
	return filepath.ToSlash(base + vs.writeExt)
}

// decodePath strips any known extension combination from the stored
// name and returns the logical base name.
func (vs *VariadicStorage) decodePath(encoded string) string {
	encoded = filepath.ToSlash(encoded)
	for _, ext := range vs.supportedExts() {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(encoded, ext) {
			return strings.TrimSuffix(encoded, ext)
		}
	}
	return encoded
}

// findExistingName tries all known extensions for the given logical base
// name and returns the first existing stored name, or fs.ErrNotExist.
func (vs *VariadicStorage) findExistingName(ctx context.Context, base string) (string, error) {
	base = filepath.ToSlash(base)
	for _, ext := range vs.supportedExts() {
		candidate := base + ext
		ok, err := vs.Backend.Exists(ctx, candidate)
		if err != nil {
			return "", err
		}
		if ok {
			return candidate, nil
		}
	}
	return "", fs.ErrNotExist
}

// Put writes the given reader using the configured writeExt. Callers
// pass only the logical name, e.g. "000000010000000000000001".
func (vs *VariadicStorage) Put(ctx context.Context, path string, r io.Reader) error {
	path = filepath.ToSlash(path)
	stored := vs.encodePath(path)

	t := vs.transformsFromName(stored)

	// Compress + encrypt according to the chosen extension.
	transformed, err := pipe.CompressAndEncryptOptional(r, t.compressor, t.crypter)
	if err != nil {
		return err
	}

	return vs.Backend.Put(ctx, stored, transformed)
}

// Get returns a reader for the object. Callers pass the logical name;
// the storage will find whichever variant (plain/gz/zst/gz.aes/zst.aes)
// actually exists and decode based only on its extension.
func (vs *VariadicStorage) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	path = filepath.ToSlash(path)

	// First, see if caller already included a known extension.
	for _, ext := range vs.supportedExts() {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(path, ext) {
			// Treat as a fully encoded path.
			rc, err := vs.Backend.Get(ctx, path)
			if err != nil {
				return nil, err
			}
			t := vs.transformsFromName(path)
			return pipe.DecryptAndDecompressOptional(rc, t.crypter, t.decompressor)
		}
	}

	// Otherwise, treat as base and search for existing variant.
	stored, err := vs.findExistingName(ctx, path)
	if err != nil {
		return nil, err
	}

	rc, err := vs.Backend.Get(ctx, stored)
	if err != nil {
		return nil, err
	}

	t := vs.transformsFromName(stored)
	return pipe.DecryptAndDecompressOptional(rc, t.crypter, t.decompressor)
}

// List lists FileInfo entries but rewrites the Path field to the
// logical name (without extensions).
func (vs *VariadicStorage) List(ctx context.Context, prefix string) ([]FileInfo, error) {
	prefix = filepath.ToSlash(prefix)
	files, err := vs.Backend.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	for i := range files {
		files[i].Path = vs.decodePath(files[i].Path)
	}
	return files, nil
}

func (vs *VariadicStorage) ListInfoRaw(ctx context.Context, prefix string) ([]FileInfo, error) {
	prefix = filepath.ToSlash(prefix)
	files, err := vs.Backend.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	return files, nil
}

// Delete deletes all known variants for the given logical path.
// If you want "only current writeExt" semantics, you can change
// this to use vs.encodePath() instead.
func (vs *VariadicStorage) Delete(ctx context.Context, path string) error {
	path = filepath.ToSlash(path)

	var lastErr error
	for _, ext := range vs.supportedExts() {
		candidate := path + ext
		if err := vs.Backend.Delete(ctx, candidate); err != nil && !errors.Is(err, fs.ErrNotExist) {
			lastErr = err
		}
	}
	return lastErr
}

func (vs *VariadicStorage) DeleteDir(ctx context.Context, path string) error {
	path = filepath.ToSlash(path)
	return vs.Backend.DeleteDir(ctx, path)
}

// Exists returns true if any variant for the logical path exists.
func (vs *VariadicStorage) Exists(ctx context.Context, path string) (bool, error) {
	path = filepath.ToSlash(path)
	_, err := vs.findExistingName(ctx, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListTopLevelDirs just delegates to the backend; directory names
// usually don't contain transform suffixes.
func (vs *VariadicStorage) ListTopLevelDirs(ctx context.Context, prefix string) (map[string]bool, error) {
	prefix = filepath.ToSlash(prefix)
	return vs.Backend.ListTopLevelDirs(ctx, prefix)
}

// ListPrefix returns FileInfo entries for all stored objects whose path starts
// with the given prefix, stripping known codec extensions from the results.
func (vs *VariadicStorage) ListPrefix(ctx context.Context, prefix string) ([]FileInfo, error) {
	prefix = filepath.ToSlash(prefix)
	files, err := vs.Backend.ListPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	for i := range files {
		files[i].Path = vs.decodePath(files[i].Path)
	}
	return files, nil
}

func (vs *VariadicStorage) Rename(ctx context.Context, oldRemotePath, newRemotePath string) error {
	// Normalize and strip transform extensions to get logical names
	oldBase := vs.decodePath(filepath.ToSlash(oldRemotePath))
	newBase := vs.decodePath(filepath.ToSlash(newRemotePath))

	if oldBase == newBase {
		return nil
	}

	var lastErr error

	for _, ext := range vs.supportedExts() {
		oldPhys := oldBase + ext
		newPhys := newBase + ext

		// Check if this physical variant exists
		ok, err := vs.Backend.Exists(ctx, oldPhys)
		if err != nil {
			lastErr = err
			continue
		}
		if !ok {
			continue
		}

		if err := vs.Backend.Rename(ctx, oldPhys, newPhys); err != nil {
			lastErr = err
		}
	}

	return lastErr
}
