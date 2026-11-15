package main

// Allowed paths, the secret list, File manifests, uploads, Quarantine and Restore.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// Limits of defaulted decision 23. Variables only so tests can lower them.
var (
	maxFiles      = 50000
	hashLimit     = int64(512 << 20)
	walkDeadline  = 4 * time.Minute
	maxUploadFile = int64(1 << 20)
	maxUploadBody = 16 << 20
	maxReportBody = 16 << 20 // B01's File manifest cap
	maxSmallBody  = 64 << 10 // B01's cap for every other request
	maxCmdFiles   = 100
	maxPathBytes  = 4096
)

const defaultStateDir = "/var/lib/asset-monitor-agent"

var systemDirs = []string{"/etc", "/usr", "/boot", "/root", "/proc", "/sys", "/dev", "/run", "/bin", "/sbin", "/lib", "/lib64", defaultStateDir}

// unitSafe keeps a path writable into a systemd unit without quoting or % specifiers.
var unitSafe = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]*$`)

func within(p, dir string) bool {
	return dir == "/" || p == dir || strings.HasPrefix(p, dir+"/")
}

// refusePath applies the B03 refusals to a clean absolute real path.
// extra holds the state directory, the Quarantine folder and the configuration directory.
func refusePath(p string, extra ...string) error {
	if p == "/" {
		return errors.New("/ is refused")
	}
	if !unitSafe.MatchString(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%q: only clean absolute paths of A-Z a-z 0-9 . _ / @ + - are accepted", p)
	}
	for _, d := range append(append([]string{}, systemDirs...), extra...) {
		forms := []string{d}
		if r, err := filepath.EvalSymlinks(d); err == nil && r != d {
			forms = append(forms, r)
		}
		for _, f := range forms {
			if within(p, f) || within(f, p) {
				return fmt.Errorf("%s is refused: it overlaps %s", p, d)
			}
		}
	}
	return nil
}

// resolveAllowed resolves an --allow value to its real directory and applies the refusals.
func resolveAllowed(p string, extra ...string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%q: --allow needs an absolute path", p)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory", real)
	}
	return real, refusePath(real, extra...)
}

// --- the secret list (B05), read from code ---

var (
	secretDirs  = map[string]bool{".ssh": true, ".gnupg": true, ".aws": true, ".composer": true, ".config": true, ".git": true}
	secretNames = map[string]bool{"authorized_keys": true, ".htpasswd": true, "auth.json": true, ".git-credentials": true, ".netrc": true,
		".my.cnf": true, ".pgpass": true, ".npmrc": true, "configuration.php": true, "localsettings.php": true}
	secretGlobs = []string{".env*", "wp-config*", "*_history", "*.sql*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.kdbx", "*.sqlite", "*.db"}
)

// isSecret reports whether the bytes at an absolute path may never be uploaded. Case is ignored.
func isSecret(full string) bool {
	parts := strings.Split(strings.ToLower(full), "/")
	n := len(parts)
	name := parts[n-1]
	for _, d := range parts[:n-1] {
		if secretDirs[d] {
			return true
		}
	}
	if secretNames[name] || (strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub")) {
		return true
	}
	for _, g := range secretGlobs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return (n >= 3 && parts[n-3] == "sites" && name == "settings.php") ||
		(n >= 3 && parts[n-3] == "app" && parts[n-2] == "etc" && name == "env.php")
}

// validRel checks a path relative to a Watched root: normalized, no NUL, no "..", at most 4,096 bytes.
func validRel(p string) bool {
	return p != "" && p != "." && len(p) <= maxPathBytes && utf8.ValidString(p) && !strings.ContainsRune(p, 0) &&
		!strings.HasPrefix(p, "/") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}

// --- File manifests ---

type entry struct {
	Path          string `json:"path"`
	Type          string `json:"type"` // file | symlink
	SHA256        string `json:"sha256,omitempty"`
	Size          int64  `json:"size"`
	Mode          uint32 `json:"mode"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	Mtime         int64  `json:"mtime"`
	Target        string `json:"target,omitempty"`
	Secret        bool   `json:"secret,omitempty"`
	OverHashLimit bool   `json:"over_hash_limit,omitempty"`
}

type rootManifest struct {
	Root    string  `json:"root"`
	Entries []entry `json:"entries"`
}

type issue struct {
	Reason string `json:"reason"`
	Root   string `json:"root,omitempty"`
	Path   string `json:"path,omitempty"`
}

type report struct {
	Sequence       int64          `json:"sequence"`
	ConfigSequence int64          `json:"config_sequence"`
	Reason         string         `json:"reason"`
	StartedAt      int64          `json:"started_at"`
	FinishedAt     int64          `json:"finished_at"`
	FileCount      int            `json:"file_count"`
	OverLimit      bool           `json:"over_limit"`
	CutShort       bool           `json:"cut_short"`
	Issues         []issue        `json:"issues"`
	Roots          []rootManifest `json:"roots"`
}

type loc struct {
	root, rel string
	size      int64
	secret    bool
}

func statT(fi fs.FileInfo) *syscall.Stat_t {
	st, _ := fi.Sys().(*syscall.Stat_t)
	if st == nil {
		st = &syscall.Stat_t{}
	}
	return st
}

// openVerified opens a regular file inside r and checks that the open descriptor is the
// file Lstat saw, so a swap for a link or another file between the two is caught.
func openVerified(r *os.Root, rel string) (*os.File, fs.FileInfo, error) {
	fi, err := r.Lstat(rel)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fi, errNotRegular
	}
	f, err := r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fi, err
	}
	got, err := f.Stat()
	if err != nil || !os.SameFile(fi, got) || !got.Mode().IsRegular() {
		f.Close()
		return nil, fi, errChanged
	}
	return f, got, nil
}

var (
	errNotRegular = errors.New("not a regular file")
	errChanged    = errors.New("changed while being read")
	errLink       = errors.New("symbolic link component")
)

var errTooLarge = errors.New("over the hashing limit")

// copyHashed copies and hashes at most hashLimit bytes, so a file that keeps growing
// (a sparse file extended in a loop) can neither stall the agent nor fill its disk.
func copyHashed(dst io.Writer, src io.Reader) (string, error) {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, hashLimit+1))
	if err == nil && n > hashLimit {
		err = errTooLarge
	}
	return hex.EncodeToString(h.Sum(nil)), err
}

func hashReader(rd io.Reader) (string, error) { return copyHashed(io.Discard, rd) }

// walk builds the File manifest of the Watched roots. It never follows a link and never truncates:
// over the file limit it returns an over-limit report with no entries.
func walk(ctx context.Context, roots []string, check func(string) error) (report, map[string][]loc) {
	ctx, cancel := context.WithTimeout(ctx, walkDeadline)
	defer cancel()
	var rep report
	index := map[string][]loc{}
	count := 0
	add := func(reason, root, p string) { rep.Issues = append(rep.Issues, issue{reason, root, p}) }
	for _, root := range roots {
		if rep.OverLimit || rep.CutShort && ctx.Err() != nil {
			break
		}
		if err := check(root); err != nil {
			add("root_refused", root, "")
			continue
		}
		r, err := openDir(root)
		if err != nil {
			add("root_refused", root, "")
			continue
		}
		rm := rootManifest{Root: root, Entries: []entry{}}
		_ = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				rep.CutShort = true
				add("deadline", root, "")
				return fs.SkipAll
			}
			if err != nil {
				add("read_error", root, p)
				return nil
			}
			if p == "." {
				return nil
			}
			if len(p) > maxPathBytes || !utf8.ValidString(p) {
				rep.CutShort = true
				reason := "path_too_long"
				if !utf8.ValidString(p) {
					reason = "bad_name"
				}
				add(reason, root, "")
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			fi, err := r.Lstat(p)
			if err != nil || fi.IsDir() != d.IsDir() {
				add("changed_during_walk", root, p)
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			mode := fi.Mode()
			if mode.IsDir() || !(mode.IsRegular() || mode&fs.ModeSymlink != 0) {
				return nil // directories are walked, devices, sockets and pipes skipped
			}
			if count++; count > maxFiles {
				rep.OverLimit = true
				return fs.SkipAll
			}
			st := statT(fi)
			e := entry{Path: p, Type: "file", Size: fi.Size(), Mode: uint32(st.Mode) & 0o7777, UID: st.Uid, GID: st.Gid,
				Mtime: fi.ModTime().Unix(), Secret: isSecret(root + "/" + p)}
			if mode&fs.ModeSymlink != 0 {
				e.Type = "symlink"
				if e.Target, err = r.Readlink(p); err != nil || !utf8.ValidString(e.Target) {
					add("bad_name", root, p)
					return nil
				}
			} else if fi.Size() > hashLimit {
				e.OverHashLimit = true
				add("over_hash_limit", root, p)
			} else {
				f, _, err := openVerified(r, p)
				if err != nil {
					add("changed_during_walk", root, p)
					return nil
				}
				e.SHA256, err = hashReader(f)
				f.Close()
				switch {
				case errors.Is(err, errTooLarge): // it grew past the limit while being read
					e.SHA256, e.OverHashLimit = "", true
					add("over_hash_limit", root, p)
				case err != nil:
					add("read_error", root, p)
					return nil
				default:
					index[e.SHA256] = append(index[e.SHA256], loc{root, p, e.Size, e.Secret})
				}
			}
			rm.Entries = append(rm.Entries, e)
			return nil
		})
		r.Close()
		rep.Roots = append(rep.Roots, rm)
	}
	rep.FileCount = count
	if rep.OverLimit {
		rep.Roots, index = []rootManifest{}, map[string][]loc{}
		rep.FileCount = maxFiles + 1
		add("over_file_limit", "", "")
	}
	if rep.Roots == nil {
		rep.Roots = []rootManifest{}
	}
	return rep, index
}

// readWanted returns the bytes of one wanted SHA-256 from the latest manifest, re-hashed now,
// or the reason it is not uploaded.
func readWanted(sum string, index map[string][]loc, check func(string) error) ([]byte, string) {
	locs := index[sum]
	if len(locs) == 0 {
		return nil, "not_in_manifest"
	}
	for _, l := range locs {
		if l.secret || isSecret(l.root+"/"+l.rel) {
			return nil, "secret" // identical bytes to a secret file are a secret too
		}
	}
	why := "gone_or_changed"
	for _, l := range locs {
		if l.size > maxUploadFile {
			return nil, "too_large"
		}
		if check(l.root) != nil {
			continue
		}
		r, err := openDir(l.root)
		if err != nil {
			continue
		}
		f, fi, err := openVerified(r, l.rel)
		r.Close()
		if err != nil {
			continue
		}
		if statT(fi).Nlink != 1 { // maybe another name of a file outside the Watched roots
			f.Close()
			why = "hard_link"
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxUploadFile+1))
		f.Close()
		if err != nil {
			continue
		}
		if int64(len(data)) > maxUploadFile {
			return nil, "too_large"
		}
		if h := sha256.Sum256(data); hex.EncodeToString(h[:]) == sum {
			return data, ""
		}
	}
	return nil, why
}

// --- Quarantine and Restore (B08, decision 27) ---

type qmeta struct {
	ID            string `json:"id"`
	Root          string `json:"root"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	Mode          uint32 `json:"mode"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	MtimeNs       int64  `json:"mtime_ns"`
	QuarantinedAt int64  `json:"quarantined_at"`
}

type journalEntry struct {
	Op    string `json:"op"`    // quarantine | restore
	Stage string `json:"stage"` // aside | copied | created
	Meta  qmeta  `json:"meta"`
	Aside string `json:"aside,omitempty"`
	Dev   uint64 `json:"dev,omitempty"`
	Ino   uint64 `json:"ino,omitempty"`
}

type fileResult struct {
	Root         string `json:"root,omitempty"`
	Path         string `json:"path,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	QuarantineID string `json:"quarantine_id,omitempty"`
	Status       string `json:"status"`
	Detail       string `json:"detail,omitempty"`
}

// vault is the state directory's Quarantine folder and journal.
type vault struct {
	q, j *os.Root
}

func openVault(stateDir string) (*vault, error) {
	for _, d := range []string{stateDir, stateDir + "/quarantine", stateDir + "/journal"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	q, err := os.OpenRoot(stateDir + "/quarantine")
	if err != nil {
		return nil, err
	}
	j, err := os.OpenRoot(stateDir + "/journal")
	if err != nil {
		q.Close()
		return nil, err
	}
	return &vault{q, j}, nil
}

func writeExcl(r *os.Root, name string, data []byte) error {
	f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (v *vault) journal(j journalEntry) error {
	data, _ := json.Marshal(j)
	tmp := j.Meta.ID + ".tmp"
	_ = v.j.Remove(tmp)
	if err := writeExcl(v.j, tmp, data); err != nil {
		return err
	}
	return v.j.Rename(tmp, j.Meta.ID+".json")
}

func (v *vault) unjournal(id string) { _ = v.j.Remove(id + ".json") }

// descend opens each directory of parts in turn below r, which it closes, refusing a
// symbolic link at any step. Each step is checked to be the directory Lstat saw.
func descend(r *os.Root, parts []string) (*os.Root, error) {
	for _, c := range parts {
		fi, err := r.Lstat(c)
		if err != nil {
			r.Close()
			return nil, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			r.Close()
			return nil, errLink
		}
		if !fi.IsDir() {
			r.Close()
			return nil, errNotRegular
		}
		next, err := r.OpenRoot(c)
		r.Close()
		if err != nil {
			return nil, err
		}
		if st, err := next.Stat("."); err != nil || !os.SameFile(fi, st) {
			next.Close()
			return nil, errLink
		}
		r = next
	}
	return r, nil
}

// openDir opens the absolute directory abs from /, refusing a symbolic link at any component,
// so a Watched root (or a parent) swapped for a link after it was checked cannot redirect the agent.
func openDir(abs string) (*os.Root, error) {
	if !filepath.IsAbs(abs) || filepath.Clean(abs) != abs {
		return nil, errors.New("not a clean absolute path")
	}
	r, err := os.OpenRoot("/")
	if err != nil || abs == "/" {
		return r, err
	}
	return descend(r, strings.Split(abs[1:], "/"))
}

// openParent opens the directory that holds rel, inside root, refusing any symbolic link
// component of root or below it.
func openParent(root, rel string) (*os.Root, string, error) {
	r, err := openDir(root)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(rel, "/")
	if r, err = descend(r, parts[:len(parts)-1]); err != nil {
		return nil, "", err
	}
	return r, parts[len(parts)-1], nil
}

func isLinkErr(err error) bool { return errors.Is(err, errLink) }

// putBack links the aside name to the original name, which never replaces a file, then drops the aside name.
func putBack(p *os.Root, aside, name string) error {
	if err := p.Link(aside, name); err != nil {
		return fmt.Errorf("left at %s: %w", aside, err)
	}
	return p.Remove(aside)
}

func hashFile(r *os.Root, name string) string {
	f, err := r.Open(name)
	if err != nil {
		return ""
	}
	defer f.Close()
	sum, err := hashReader(f)
	if err != nil {
		return ""
	}
	return sum
}

// quarantine moves one file into the Quarantine folder if its bytes still hash to sum.
func (v *vault) quarantine(root, rel, sum string, now time.Time) fileResult {
	res := fileResult{Root: root, Path: rel, SHA256: sum}
	fail := func(status string, err error) fileResult {
		res.Status = status
		if err != nil {
			res.Detail = err.Error()
		}
		return res
	}
	p, name, err := openParent(root, rel)
	switch {
	case isLinkErr(err):
		return fail("link_refused", nil)
	case errors.Is(err, fs.ErrNotExist):
		return fail("not_present", nil)
	case err != nil:
		return fail("failed", err)
	}
	defer p.Close()
	fi, err := p.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fail("not_present", nil)
	case err != nil:
		return fail("failed", err)
	case fi.Mode()&fs.ModeSymlink != 0:
		return fail("link_refused", nil)
	case !fi.Mode().IsRegular():
		return fail("failed", errNotRegular)
	}
	// Check the bytes before touching anything.
	f, _, err := openVerified(p, name)
	if err != nil {
		return fail("failed", err)
	}
	got, err := hashReader(f)
	f.Close()
	if err != nil {
		return fail("failed", err)
	}
	if got != sum {
		return fail("hash_mismatch", nil)
	}

	id := randHex(16)
	aside := ".am-aside-" + id // no executable extension, and nothing of the original name
	if _, err := p.Lstat(aside); !errors.Is(err, fs.ErrNotExist) {
		return fail("failed", errors.New("aside name taken"))
	}
	st := statT(fi)
	meta := qmeta{ID: id, Root: root, Path: rel, SHA256: sum, Size: fi.Size(), Mode: uint32(st.Mode) & 0o7777,
		UID: st.Uid, GID: st.Gid, MtimeNs: fi.ModTime().UnixNano(), QuarantinedAt: now.Unix()}
	if err := v.journal(journalEntry{Op: "quarantine", Stage: "aside", Meta: meta, Aside: aside}); err != nil {
		return fail("failed", err)
	}
	if err := p.Rename(name, aside); err != nil {
		v.unjournal(id)
		return fail("failed", err)
	}
	undo := func(status string, cause error) fileResult {
		_ = v.q.Remove(id + ".bin")
		_ = v.q.Remove(id + ".json")
		if err := putBack(p, aside, name); err != nil {
			v.unjournal(id)
			return fail("failed", err)
		}
		v.unjournal(id)
		return fail(status, cause)
	}
	src, afi, err := openVerified(p, aside)
	if err != nil {
		if afi != nil && afi.Mode()&fs.ModeSymlink != 0 {
			return undo("link_refused", nil)
		}
		return undo("failed", err)
	}
	if !os.SameFile(fi, afi) {
		src.Close()
		return undo("hash_mismatch", errors.New("file swapped before the move"))
	}
	dst, err := v.q.OpenFile(id+".bin", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		src.Close()
		return undo("failed", err)
	}
	got, err = copyHashed(dst, src)
	src.Close()
	if err == nil {
		err = dst.Sync()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return undo("failed", err)
	}
	if got != sum {
		return undo("hash_mismatch", nil)
	}
	if hashFile(v.q, id+".bin") != sum {
		return undo("failed", errors.New("quarantined copy does not verify"))
	}
	data, _ := json.Marshal(meta)
	if err := writeExcl(v.q, id+".json", data); err != nil {
		return undo("failed", err)
	}
	if err := v.journal(journalEntry{Op: "quarantine", Stage: "copied", Meta: meta, Aside: aside}); err != nil {
		return fail("failed", err)
	}
	res.QuarantineID = id
	if cur, err := p.Lstat(aside); err != nil || !os.SameFile(cur, afi) {
		v.unjournal(id)
		return fail("failed", errors.New("aside name changed; nothing removed"))
	}
	if err := p.Remove(aside); err != nil {
		return fail("failed", err)
	}
	v.unjournal(id)
	res.Status = "quarantined"
	return res
}

func (v *vault) meta(id string) (qmeta, error) {
	var m qmeta
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return m, errors.New("bad quarantine id")
	}
	data, err := v.q.ReadFile(id + ".json")
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil || m.ID != id || !validRel(m.Path) {
		return m, errors.New("bad quarantine record")
	}
	return m, nil
}

// applyMeta sets owner, mode without setuid or setgid, and mtime on the open descriptor.
func applyMeta(f *os.File, m qmeta) error {
	if err := f.Chown(int(m.UID), int(m.GID)); err != nil {
		return err
	}
	mode := fs.FileMode(m.Mode & 0o777)
	if m.Mode&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	tv := []syscall.Timeval{syscall.NsecToTimeval(time.Now().UnixNano()), syscall.NsecToTimeval(m.MtimeNs)}
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var terr error
	if err := rc.Control(func(fd uintptr) { terr = syscall.Futimes(int(fd), tv) }); err != nil {
		return err
	}
	return terr
}

// restore puts one quarantine entry back at its recorded path, never over an existing file.
// check validates the recorded root against the current Allowed paths and Watched roots.
func (v *vault) restore(id string, check func(string) error) fileResult {
	res := fileResult{QuarantineID: id}
	fail := func(status string, err error) fileResult {
		res.Status = status
		if err != nil {
			res.Detail = err.Error()
		}
		return res
	}
	m, err := v.meta(id)
	if err != nil {
		return fail("failed", err)
	}
	res.Root, res.Path, res.SHA256 = m.Root, m.Path, m.SHA256
	if err := check(m.Root); err != nil {
		return fail("failed", err)
	}
	p, name, err := openParent(m.Root, m.Path)
	if err != nil {
		return fail("failed", err)
	}
	defer p.Close()
	dst, err := p.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fail("path_taken", nil)
	} else if err != nil {
		return fail("failed", err)
	}
	dfi, err := dst.Stat()
	if err != nil {
		dst.Close()
		return fail("failed", err)
	}
	st := statT(dfi)
	if err := v.journal(journalEntry{Op: "restore", Stage: "created", Meta: m, Dev: uint64(st.Dev), Ino: st.Ino}); err != nil {
		dst.Close()
		return fail("failed", err) // ponytail: leaves an empty 0600 file at the path; it is ours and holds no bytes
	}
	src, err := v.q.Open(id + ".bin")
	if err != nil {
		dst.Close()
		v.dropOwn(p, name, dfi)
		v.unjournal(id)
		return fail("failed", err)
	}
	got, err := copyHashed(dst, src)
	src.Close()
	if err == nil && got != m.SHA256 {
		err = errors.New("quarantined copy does not verify")
	}
	if err == nil {
		err = dst.Sync()
	}
	if err == nil {
		err = applyMeta(dst, m)
	}
	dst.Close()
	if err != nil {
		v.dropOwn(p, name, dfi)
		v.unjournal(id)
		return fail("failed", err)
	}
	_ = v.q.Remove(id + ".bin")
	_ = v.q.Remove(id + ".json")
	v.unjournal(id)
	res.Status = "restored"
	return res
}

// dropOwn removes a file the agent itself created exclusively, and only if it is still that file.
func (v *vault) dropOwn(p *os.Root, name string, own fs.FileInfo) {
	if cur, err := p.Lstat(name); err == nil && os.SameFile(cur, own) {
		_ = p.Remove(name)
	}
}

// recover finishes or undoes a Quarantine or Restore step a stopped agent had begun.
func (v *vault) recover(logf func(string, ...any)) {
	names, _ := fs.Glob(v.j.FS(), "*.json")
	for _, n := range names {
		var j journalEntry
		data, err := v.j.ReadFile(n)
		if err != nil || json.Unmarshal(data, &j) != nil || j.Meta.ID+".json" != n || !validRel(j.Meta.Path) {
			logf("journal: unreadable entry %s left in place", n)
			continue
		}
		m := j.Meta
		p, name, err := openParent(m.Root, m.Path)
		if err != nil {
			logf("journal %s: %v; left in place", m.ID, err)
			continue
		}
		switch j.Op + "/" + j.Stage {
		case "quarantine/aside": // the copy was not verified: undo
			_ = v.q.Remove(m.ID + ".bin")
			_ = v.q.Remove(m.ID + ".json")
			if _, err := p.Lstat(j.Aside); err == nil {
				if err := putBack(p, j.Aside, name); err != nil {
					logf("journal %s: put back: %v", m.ID, err)
				}
			}
		case "quarantine/copied": // the copy verified: finish
			if hashFile(v.q, m.ID+".bin") == m.SHA256 {
				if fi, err := p.Lstat(j.Aside); err == nil && fi.Mode().IsRegular() && hashFile(p, j.Aside) == m.SHA256 {
					_ = p.Remove(j.Aside)
				}
			}
		case "restore/created": // finish it if the copy is whole, else drop it; only the inode it created
			if f, fi, err := openVerified(p, name); err == nil {
				if st := statT(fi); uint64(st.Dev) == j.Dev && st.Ino == j.Ino {
					if sum, err := hashReader(f); err == nil && sum == m.SHA256 {
						if applyMeta(f, m) == nil {
							_ = v.q.Remove(m.ID + ".bin")
							_ = v.q.Remove(m.ID + ".json")
						}
					} else {
						v.dropOwn(p, name, fi)
					}
				}
				f.Close()
			}
		}
		p.Close()
		v.unjournal(m.ID)
		logf("journal %s: %s step recovered", m.ID, j.Op)
	}
}
