package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	version        = "0.2.0"
	apeBlock       = int64(4096)
	apeMinPrologue = int64(16 << 10)
)

type target struct {
	OS   string
	Arch string
}

func (t target) String() string { return t.OS + "/" + t.Arch }

var commonTargets = []target{
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"freebsd", "amd64"},
	{"freebsd", "arm64"},
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"netbsd", "amd64"},
	{"netbsd", "arm64"},
	{"openbsd", "amd64"},
	{"openbsd", "arm64"},
	{"windows", "amd64"},
}

type options struct {
	output  string
	targets string
	jobs    int
	rebuild bool
	verbose bool
	version bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var o options
	fs := flag.NewFlagSet("gourun", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.output, "o", "", "write an APE instead of running the script")
	fs.StringVar(&o.targets, "targets", "common", "comma-separated GOOS/GOARCH targets")
	fs.IntVar(&o.jobs, "j", minInt(runtime.NumCPU(), 4), "parallel cross-builds")
	fs.BoolVar(&o.rebuild, "rebuild", false, "ignore cached builds")
	fs.BoolVar(&o.verbose, "v", false, "print timestamped build events")
	fs.BoolVar(&o.version, "version", false, "print version")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: gourun [flags] script.go [args...]")
		fmt.Fprintln(stderr, "       gourun -o program.com [-targets common] script.go")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if o.version {
		fmt.Fprintf(stdout, "gourun %s\n", version)
		return 0
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	if o.jobs < 1 {
		fmt.Fprintln(stderr, "gourun: -j must be positive")
		return 2
	}

	src, err := loadSource(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "gourun: %v\n", err)
		return 1
	}
	defer src.close()

	b, err := newBuilder(o, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "gourun: %v\n", err)
		return 1
	}
	if o.output == "" {
		a, err := b.build(ctx, src, target{runtime.GOOS, runtime.GOARCH})
		if err != nil {
			fmt.Fprintf(stderr, "gourun: %v\n", err)
			return 1
		}
		return runBinary(ctx, a.Path, fs.Args()[1:], stdout, stderr)
	}

	targets, err := parseTargets(o.targets)
	if err != nil {
		fmt.Fprintf(stderr, "gourun: %v\n", err)
		return 2
	}
	artifacts, err := b.buildMany(ctx, src, targets, o.jobs)
	if err != nil {
		fmt.Fprintf(stderr, "gourun: %v\n", err)
		return 1
	}
	path, err := writeAPE(o.output, artifacts)
	if err != nil {
		fmt.Fprintf(stderr, "gourun: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, path)
	return 0
}

func runBinary(ctx context.Context, path string, args []string, stdout, stderr io.Writer) int {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	fmt.Fprintf(stderr, "gourun: %v\n", err)
	return 1
}

type source struct {
	Path    string
	Dir     string
	Clean   []byte
	Overlay string
	temp    string
}

func loadSource(path string) (*source, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	if len(data) >= 2 && data[0] == '#' && data[1] == '!' {
		data = append([]byte(nil), data...)
		data[0], data[1] = '/', '/'
	}
	temp, err := os.MkdirTemp("", "gourun-overlay-")
	if err != nil {
		return nil, err
	}
	clean := filepath.Join(temp, "script.go")
	if err := os.WriteFile(clean, data, 0600); err != nil {
		os.RemoveAll(temp)
		return nil, err
	}
	overlay := filepath.Join(temp, "overlay.json")
	blob, err := json.Marshal(struct {
		Replace map[string]string
	}{map[string]string{abs: clean}})
	if err != nil {
		os.RemoveAll(temp)
		return nil, err
	}
	if err := os.WriteFile(overlay, blob, 0600); err != nil {
		os.RemoveAll(temp)
		return nil, err
	}
	return &source{Path: abs, Dir: filepath.Dir(abs), Clean: data, Overlay: overlay, temp: temp}, nil
}

func (s *source) close() { os.RemoveAll(s.temp) }

type builder struct {
	cache     string
	goVersion string
	rebuild   bool
	buildVCS  bool
	verbose   bool
	stderr    io.Writer
}

type artifact struct {
	Target target
	Path   string
	Size   int64
	Digest [sha256.Size]byte
}

func newBuilder(o options, stderr io.Writer) (*builder, error) {
	cache, err := os.UserCacheDir()
	if err != nil || cache == "" {
		cache = os.TempDir()
	}
	out, err := exec.Command("go", "version").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go version: %s", strings.TrimSpace(string(out)))
	}
	version := strings.TrimSpace(string(out))
	return &builder{
		cache:     filepath.Join(cache, "gourun", "v2"),
		goVersion: version,
		buildVCS:  supportsBuildVCS(version),
		rebuild:   o.rebuild,
		verbose:   o.verbose,
		stderr:    stderr,
	}, nil
}

func supportsBuildVCS(version string) bool {
	return goMinor(version) >= 18
}

func goMinor(version string) int {
	i := strings.Index(version, "go1.")
	if i < 0 {
		return 0
	}
	i += len("go1.")
	n := 0
	for ; i < len(version); i++ {
		c := version[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func (b *builder) log(t target, format string, args ...interface{}) {
	if !b.verbose {
		return
	}
	fmt.Fprintf(b.stderr, "%s [%s] %s\n", time.Now().UTC().Format(time.RFC3339), t, fmt.Sprintf(format, args...))
}

func (b *builder) build(ctx context.Context, src *source, t target) (artifact, error) {
	key, err := b.inputKey(ctx, src, t)
	if err != nil {
		return artifact{}, err
	}
	ext := ""
	if t.OS == "windows" {
		ext = ".exe"
	}
	dir := filepath.Join(b.cache, key)
	path := filepath.Join(dir, "program"+ext)
	if !b.rebuild {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
			b.log(t, "cache hit")
			return inspectArtifact(t, path)
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return artifact{}, err
	}
	tmp, err := os.CreateTemp(dir, ".program-*")
	if err != nil {
		return artifact{}, err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return artifact{}, err
	}
	os.Remove(tmpPath)
	defer os.Remove(tmpPath)

	b.log(t, "building")
	args := []string{
		"build",
		"-overlay=" + src.Overlay,
		"-trimpath",
	}
	if b.buildVCS {
		args = append(args, "-buildvcs=false")
	}
	args = append(args, "-ldflags=-s -w -buildid=", "-o", tmpPath, src.Path)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = src.Dir
	cmd.Env = buildEnv(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return artifact{}, fmt.Errorf("%s: go build: %w\n%s", t, err, bytes.TrimSpace(out))
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return artifact{}, err
	}
	if err := replaceFile(tmpPath, path); err != nil {
		return artifact{}, err
	}
	b.log(t, "built")
	return inspectArtifact(t, path)
}

func inspectArtifact(t target, path string) (artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return artifact{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return artifact{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return artifact{Target: t, Path: path, Size: n, Digest: digest}, nil
}

func (b *builder) buildMany(ctx context.Context, src *source, targets []target, jobs int) ([]artifact, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type job struct {
		index int
		t     target
	}
	todos := make(chan job)
	results := make(chan struct {
		index int
		a     artifact
		err   error
	}, len(targets))
	workers := minInt(jobs, len(targets))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range todos {
				a, err := b.build(ctx, src, j.t)
				results <- struct {
					index int
					a     artifact
					err   error
				}{j.index, a, err}
				if err != nil {
					cancel()
				}
			}
		}()
	}
	go func() {
		defer close(todos)
		for i, t := range targets {
			select {
			case todos <- job{i, t}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]artifact, len(targets))
	var first error
	for r := range results {
		if r.err != nil && first == nil {
			first = r.err
		}
		if r.err == nil {
			out[r.index] = r.a
		}
	}
	if first != nil {
		return nil, first
	}
	return out, nil
}

type moduleInfo struct {
	Path      string
	Version   string
	Sum       string
	GoMod     string
	GoModSum  string
	GoVersion string
	Replace   *moduleInfo
}

type packageInfo struct {
	ImportPath string
	Dir        string
	Standard   bool
	GoFiles    []string
	HFiles     []string
	SFiles     []string
	SysoFiles  []string
	EmbedFiles []string
	Module     *moduleInfo
}

func (b *builder) inputKey(ctx context.Context, src *source, t target) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-json", "-overlay="+src.Overlay, src.Path)
	cmd.Dir = src.Dir
	cmd.Env = buildEnv(t)
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", fmt.Errorf("%s: go list: %s", t, bytes.TrimSpace(exit.Stderr))
		}
		return "", fmt.Errorf("%s: go list: %w", t, err)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	var packages []packageInfo
	for {
		var p packageInfo
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if !p.Standard {
			packages = append(packages, p)
		}
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].ImportPath < packages[j].ImportPath })
	h := sha256.New()
	stamp(h, "gourun-input-v2", b.goVersion, t.String())
	seen := map[string]bool{}
	for _, p := range packages {
		stamp(h, "package", p.ImportPath, moduleStamp(p.Module))
		if !isLocalModule(p.Module) {
			continue
		}
		for _, name := range packageFiles(p) {
			path := name
			if !filepath.IsAbs(path) {
				path = filepath.Join(p.Dir, path)
			}
			path = filepath.Clean(path)
			if seen[path] {
				continue
			}
			seen[path] = true
			data := src.Clean
			if path != src.Path {
				var err error
				data, err = os.ReadFile(path)
				if err != nil {
					return "", fmt.Errorf("hash %s: %w", path, err)
				}
			}
			stamp(h, "file", filepath.ToSlash(name), string(data))
		}
		m := effectiveModule(p.Module)
		if m != nil && m.GoMod != "" && !seen[m.GoMod] {
			data, err := os.ReadFile(m.GoMod)
			if err != nil {
				return "", err
			}
			seen[m.GoMod] = true
			stamp(h, "gomod", string(data))
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func stamp(h hash.Hash, values ...string) {
	var size [8]byte
	for _, value := range values {
		binary.LittleEndian.PutUint64(size[:], uint64(len(value)))
		h.Write(size[:])
		h.Write([]byte(value))
	}
}

func moduleStamp(m *moduleInfo) string {
	if m == nil {
		return "local"
	}
	s := strings.Join([]string{m.Path, m.Version, m.Sum, m.GoModSum, m.GoVersion}, "\x00")
	if m.Replace != nil {
		s += "\x00replace\x00" + moduleStamp(m.Replace)
	}
	return s
}

func effectiveModule(m *moduleInfo) *moduleInfo {
	for m != nil && m.Replace != nil {
		m = m.Replace
	}
	return m
}

func isLocalModule(m *moduleInfo) bool {
	m = effectiveModule(m)
	return m == nil || m.Version == ""
}

func packageFiles(p packageInfo) []string {
	var files []string
	files = append(files, p.GoFiles...)
	files = append(files, p.HFiles...)
	files = append(files, p.SFiles...)
	files = append(files, p.SysoFiles...)
	files = append(files, p.EmbedFiles...)
	sort.Strings(files)
	return files
}

func buildEnv(t target) []string {
	env := os.Environ()
	env = putEnv(env, "GOOS", t.OS)
	env = putEnv(env, "GOARCH", t.Arch)
	env = putEnv(env, "CGO_ENABLED", "0")
	env = putEnv(env, "GOFLAGS", "")
	env = putEnv(env, "GOEXPERIMENT", "")
	if t.Arch == "amd64" {
		env = putEnv(env, "GOAMD64", "v1")
	}
	if t.Arch == "arm64" {
		env = putEnv(env, "GOARM64", "v8.0")
	}
	return env
}

func putEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := env[:0]
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func parseTargets(text string) ([]target, error) {
	if text == "common" {
		return append([]target(nil), commonTargets...), nil
	}
	allowed := map[target]bool{}
	for _, t := range commonTargets {
		allowed[t] = true
	}
	seen := map[target]bool{}
	var out []target
	for _, item := range strings.Split(text, ",") {
		parts := strings.Split(strings.TrimSpace(item), "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad target %q; use GOOS/GOARCH", item)
		}
		t := target{parts[0], parts[1]}
		if !allowed[t] {
			return nil, fmt.Errorf("unsupported APE target %s", t)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	win := target{"windows", "amd64"}
	if !seen[win] {
		out = append(out, win)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

type payload struct {
	Artifact artifact
	Offset   int64
	Blocks   int64
}

type elfHeader struct {
	Header []byte
	Phdrs  []byte
	Offset int64
}

func writeAPE(output string, artifacts []artifact) (string, error) {
	if len(artifacts) == 0 {
		return "", errors.New("no artifacts")
	}
	byTarget := map[target]artifact{}
	for _, a := range artifacts {
		byTarget[a.Target] = a
	}
	win, ok := byTarget[target{"windows", "amd64"}]
	if !ok {
		return "", errors.New("windows/amd64 payload is required")
	}
	pe, err := os.ReadFile(win.Path)
	if err != nil {
		return "", err
	}
	layout, err := inspectPE(pe)
	if err != nil {
		return "", err
	}

	var unix []artifact
	for _, a := range artifacts {
		if a.Target.OS != "windows" {
			unix = append(unix, a)
		}
	}
	sort.Slice(unix, func(i, j int) bool { return unix[i].Target.String() < unix[j].Target.String() })
	bundleID := bundleDigest(artifacts)

	want := apeMinPrologue
	for {
		delta := alignUp(want-int64(layout.PEOffset), int64(layout.FileAlignment))
		if delta < 0 {
			delta = 0
		}
		prefix := int64(layout.PEOffset) + delta
		windowsEnd := int64(len(pe)) + delta
		cursor := alignUp(windowsEnd, apeBlock)
		payloads := make([]payload, 0, len(unix))
		for _, a := range unix {
			blocks := alignUp(a.Size, apeBlock) / apeBlock
			payloads = append(payloads, payload{a, cursor, blocks})
			cursor += blocks * apeBlock
		}
		elfs, err := makeELFHeaders(payloads, cursor)
		if err != nil {
			return "", err
		}
		for i := range elfs {
			elfs[i].Offset = cursor
			cursor += int64(len(elfs[i].Phdrs))
		}
		body, err := makeShell(payloads, elfs, bundleID)
		if err != nil {
			return "", err
		}
		if int64(80+len(body)) >= prefix {
			want *= 2
			continue
		}
		if firstELFEnd(body) > 8192 {
			return "", errors.New("embedded ELF headers exceed APE's first-8192-byte limit")
		}

		patched, err := patchPE(pe, layout, delta)
		if err != nil {
			return "", err
		}
		header := bytes.Repeat([]byte{'\n'}, int(prefix))
		copy(header, []byte("MZqFpD='\n"))
		binary.LittleEndian.PutUint32(header[0x3c:], uint32(prefix))
		copy(header[80:], append([]byte("'\n"), body...))

		abs, err := filepath.Abs(output)
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			return "", err
		}
		tmp, err := os.CreateTemp(filepath.Dir(abs), ".gourun-ape-*")
		if err != nil {
			return "", err
		}
		tmpPath := tmp.Name()
		ok := false
		defer func() {
			tmp.Close()
			if !ok {
				os.Remove(tmpPath)
			}
		}()
		if _, err := tmp.Write(header); err != nil {
			return "", err
		}
		if _, err := tmp.Write(patched); err != nil {
			return "", err
		}
		position := prefix + int64(len(patched))
		for _, p := range payloads {
			if err := padTo(tmp, &position, p.Offset); err != nil {
				return "", err
			}
			if err := appendFile(tmp, &position, p.Artifact.Path); err != nil {
				return "", err
			}
			if err := padTo(tmp, &position, p.Offset+p.Blocks*apeBlock); err != nil {
				return "", err
			}
		}
		for _, e := range elfs {
			if err := padTo(tmp, &position, e.Offset); err != nil {
				return "", err
			}
			n, err := tmp.Write(e.Phdrs)
			position += int64(n)
			if err != nil {
				return "", err
			}
		}
		if err := tmp.Chmod(0755); err != nil {
			return "", err
		}
		if err := tmp.Sync(); err != nil {
			return "", err
		}
		if err := tmp.Close(); err != nil {
			return "", err
		}
		if err := replaceFile(tmpPath, abs); err != nil {
			return "", err
		}
		ok = true
		return abs, nil
	}
}

func bundleDigest(artifacts []artifact) string {
	copyOf := append([]artifact(nil), artifacts...)
	sort.Slice(copyOf, func(i, j int) bool { return copyOf[i].Target.String() < copyOf[j].Target.String() })
	h := sha256.New()
	for _, a := range copyOf {
		stamp(h, a.Target.String(), hex.EncodeToString(a.Digest[:]))
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func makeShell(payloads []payload, elfs []elfHeader, bundleID string) ([]byte, error) {
	var b strings.Builder
	for _, e := range elfs {
		fmt.Fprintf(&b, "# printf '%s'\n", octal(e.Header))
	}
	b.WriteString("set -eu\n")
	b.WriteString("umask 077\n")
	b.WriteString("s=$0\n")
	b.WriteString("case $s in */*) ;; *) p=$(command -v \"$s\" 2>/dev/null || :); [ -n \"$p\" ] && s=$p;; esac\n")
	b.WriteString("case \"$(uname -s)/$(uname -m)\" in\n")
	for _, p := range payloads {
		pattern, err := unamePattern(p.Artifact.Target)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "  %s) n=%s; k=%d; z=%d;;\n", pattern, strings.ReplaceAll(p.Artifact.Target.String(), "/", "-"), p.Offset/apeBlock, p.Blocks)
	}
	b.WriteString("  *) printf '%s\\n' \"gourun: unsupported $(uname -s)/$(uname -m)\" >&2; exit 126;;\n")
	b.WriteString("esac\n")
	b.WriteString("c=${XDG_CACHE_HOME:-}\n")
	b.WriteString("if [ -z \"$c\" ]; then if [ -n \"${HOME:-}\" ]; then c=$HOME/.cache; else c=${TMPDIR:-/tmp}; fi; fi\n")
	fmt.Fprintf(&b, "d=$c/gourun-ape/%s\n", bundleID)
	b.WriteString("b=$d/$n\n")
	b.WriteString("if [ ! -x \"$b\" ]; then\n")
	b.WriteString("  mkdir -p \"$d\"\n")
	b.WriteString("  t=$d/.$n.$$\n")
	b.WriteString("  trap 'rm -f \"$t\"' 0 1 2 3 15\n")
	fmt.Fprintf(&b, "  dd if=\"$s\" of=\"$t\" bs=%d skip=\"$k\" count=\"$z\" 2>/dev/null\n", apeBlock)
	b.WriteString("  chmod 700 \"$t\"\n")
	b.WriteString("  mv -f \"$t\" \"$b\"\n")
	b.WriteString("  trap - 0 1 2 3 15\n")
	b.WriteString("fi\n")
	b.WriteString("exec \"$b\" \"$@\"\n")
	b.WriteString("exit 126\n")
	return []byte(b.String()), nil
}

func firstELFEnd(body []byte) int {
	last := bytes.LastIndex(body, []byte("# printf '"))
	if last < 0 {
		return 0
	}
	end := bytes.IndexByte(body[last:], '\n')
	if end < 0 {
		return 82 + last + len(body[last:])
	}
	return 82 + last + end + 1
}

func octal(data []byte) string {
	var b strings.Builder
	b.Grow(len(data) * 4)
	for _, c := range data {
		fmt.Fprintf(&b, "\\%03o", c)
	}
	return b.String()
}

func unamePattern(t target) (string, error) {
	osName := map[string]string{
		"darwin":  "Darwin",
		"freebsd": "FreeBSD",
		"linux":   "Linux",
		"netbsd":  "NetBSD",
		"openbsd": "OpenBSD",
	}[t.OS]
	if osName == "" {
		return "", fmt.Errorf("no shell mapping for %s", t)
	}
	switch t.Arch {
	case "amd64":
		return osName + "/x86_64|" + osName + "/amd64", nil
	case "arm64":
		return osName + "/aarch64|" + osName + "/arm64", nil
	default:
		return "", fmt.Errorf("no shell mapping for %s", t)
	}
}

func makeELFHeaders(payloads []payload, phdrStart int64) ([]elfHeader, error) {
	var out []elfHeader
	cursor := phdrStart
	for _, p := range payloads {
		if p.Artifact.Target.OS != "linux" {
			continue
		}
		data, err := os.ReadFile(p.Artifact.Path)
		if err != nil {
			return nil, err
		}
		e, err := shiftedELF(data, p.Offset, cursor)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.Artifact.Target, err)
		}
		out = append(out, e)
		cursor += int64(len(e.Phdrs))
	}
	return out, nil
}

func shiftedELF(data []byte, payloadOffset, phdrOffset int64) (elfHeader, error) {
	if len(data) < 64 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return elfHeader{}, errors.New("not ELF")
	}
	if data[4] != 2 || data[5] != 1 {
		return elfHeader{}, errors.New("APE loader requires little-endian ELF64")
	}
	phoff := int64(binary.LittleEndian.Uint64(data[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(data[54:56]))
	phnum := int(binary.LittleEndian.Uint16(data[56:58]))
	if phentsize < 56 || phnum < 1 || phoff < 0 || phoff+int64(phentsize*phnum) > int64(len(data)) {
		return elfHeader{}, errors.New("bad ELF program-header table")
	}
	header := append([]byte(nil), data[:64]...)
	binary.LittleEndian.PutUint64(header[32:40], uint64(phdrOffset))
	binary.LittleEndian.PutUint64(header[40:48], 0)
	binary.LittleEndian.PutUint16(header[58:60], 0)
	binary.LittleEndian.PutUint16(header[60:62], 0)
	binary.LittleEndian.PutUint16(header[62:64], 0)
	phdrs := append([]byte(nil), data[phoff:phoff+int64(phentsize*phnum)]...)
	for i := 0; i < phnum; i++ {
		entry := phdrs[i*phentsize : (i+1)*phentsize]
		filesz := binary.LittleEndian.Uint64(entry[32:40])
		if filesz != 0 {
			off := binary.LittleEndian.Uint64(entry[8:16])
			binary.LittleEndian.PutUint64(entry[8:16], off+uint64(payloadOffset))
		}
	}
	return elfHeader{Header: header, Phdrs: phdrs}, nil
}

type peLayout struct {
	PEOffset      uint32
	FileAlignment uint32
	Sections      uint16
	COFF          int
	Optional      int
	SectionTable  int
}

func inspectPE(data []byte) (peLayout, error) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return peLayout{}, errors.New("windows payload is not PE")
	}
	peoff := binary.LittleEndian.Uint32(data[0x3c:0x40])
	if uint64(peoff)+24 > uint64(len(data)) || !bytes.Equal(data[peoff:peoff+4], []byte{'P', 'E', 0, 0}) {
		return peLayout{}, errors.New("bad PE header")
	}
	coff := int(peoff) + 4
	sections := binary.LittleEndian.Uint16(data[coff+2 : coff+4])
	optionalSize := binary.LittleEndian.Uint16(data[coff+16 : coff+18])
	optional := coff + 20
	if optional+int(optionalSize) > len(data) || optionalSize < 112 {
		return peLayout{}, errors.New("bad PE optional header")
	}
	if binary.LittleEndian.Uint16(data[optional:optional+2]) != 0x20b {
		return peLayout{}, errors.New("APE needs PE32+")
	}
	fileAlignment := binary.LittleEndian.Uint32(data[optional+36 : optional+40])
	if fileAlignment == 0 || fileAlignment&(fileAlignment-1) != 0 {
		return peLayout{}, errors.New("bad PE file alignment")
	}
	sectionTable := optional + int(optionalSize)
	if sectionTable+int(sections)*40 > len(data) {
		return peLayout{}, errors.New("bad PE section table")
	}
	return peLayout{peoff, fileAlignment, sections, coff, optional, sectionTable}, nil
}

func patchPE(data []byte, p peLayout, delta int64) ([]byte, error) {
	if delta < 0 || delta > int64(^uint32(0)) {
		return nil, errors.New("PE shift is too large")
	}
	out := append([]byte(nil), data[p.PEOffset:]...)
	shift := uint32(delta)
	coff := p.COFF - int(p.PEOffset)
	optional := p.Optional - int(p.PEOffset)
	sectionTable := p.SectionTable - int(p.PEOffset)
	add32 := func(offset int) error {
		value := binary.LittleEndian.Uint32(out[offset : offset+4])
		if value == 0 {
			return nil
		}
		if value > ^uint32(0)-shift {
			return errors.New("PE offset overflow")
		}
		binary.LittleEndian.PutUint32(out[offset:offset+4], value+shift)
		return nil
	}
	if err := add32(coff + 8); err != nil {
		return nil, err
	}
	headers := binary.LittleEndian.Uint32(out[optional+60 : optional+64])
	if headers > ^uint32(0)-shift {
		return nil, errors.New("PE header-size overflow")
	}
	binary.LittleEndian.PutUint32(out[optional+60:optional+64], headers+shift)
	binary.LittleEndian.PutUint32(out[optional+64:optional+68], 0)
	directories := binary.LittleEndian.Uint32(out[optional+108 : optional+112])
	if directories > 4 {
		if err := add32(optional + 112 + 4*8); err != nil {
			return nil, err
		}
	}
	for i := 0; i < int(p.Sections); i++ {
		section := sectionTable + i*40
		for _, offset := range []int{20, 24, 28} {
			if err := add32(section + offset); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func appendFile(dst io.Writer, position *int64, path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	n, err := io.Copy(dst, src)
	*position += n
	return err
}

func padTo(dst io.Writer, position *int64, target int64) error {
	if *position > target {
		return fmt.Errorf("layout overlap at %d > %d", *position, target)
	}
	zero := make([]byte, 32<<10)
	for *position < target {
		n := minInt64(int64(len(zero)), target-*position)
		written, err := dst.Write(zero[:n])
		*position += int64(written)
		if err != nil {
			return err
		}
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func alignUp(value, alignment int64) int64 {
	if value <= 0 {
		return 0
	}
	return (value + alignment - 1) & -alignment
}

func replaceFile(source, destination string) error {
	if err := os.Rename(source, destination); err == nil {
		return nil
	}
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}
