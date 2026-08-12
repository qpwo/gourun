package main

import (
    "bytes"
    "context"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestRunShebangScript(t *testing.T) {
    dir := t.TempDir()
    script := filepath.Join(dir, "hello.go")
    err := os.WriteFile(script, []byte("#!/nope\npackage main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() {\n\tfmt.Println(os.Args[1:])\n}\n"), 0700)
    if err != nil {
        t.Fatal(err)
    }
    var stdout bytes.Buffer
    var stderr bytes.Buffer
    code := run(context.Background(), []string{"-rebuild", script, "alpha", "beta"}, &stdout, &stderr)
    if code != 0 {
        t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
    }
    if strings.TrimSpace(stdout.String()) != "[alpha beta]" {
        t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
    }
}

func TestParseTargets(t *testing.T) {
    targets, err := parseTargets("linux/amd64,linux/amd64")
    if err != nil {
        t.Fatal(err)
    }
    if len(targets) != 2 {
        t.Fatalf("targets=%v", targets)
    }
    if targets[0] != (target{"linux", "amd64"}) {
        t.Fatalf("targets=%v", targets)
    }
    if targets[1] != (target{"windows", "amd64"}) {
        t.Fatalf("targets=%v", targets)
    }
}

func TestGoMinor(t *testing.T) {
    if goMinor("go version go1.25.4 darwin/arm64") != 25 {
        t.Fatal(goMinor("go version go1.25.4 darwin/arm64"))
    }
    if goMinor("go version go1.16.15 linux/amd64") != 16 {
        t.Fatal(goMinor("go version go1.16.15 linux/amd64"))
    }
    if goMinor("bad") != 0 {
        t.Fatal(goMinor("bad"))
    }
}
