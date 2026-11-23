// Architecture checks use parsed imports, including files excluded by build tags.
package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func module(path string) (string, string) {
	parts := strings.Split(path, "/")
	if len(parts) >= 4 && parts[0] == "internal" && parts[1] == "modules" {
		layer := "module"
		if len(parts) > 4 {
			layer = parts[3]
		}
		return parts[2], layer
	}
	return "", ""
}
func forbidden(src, dep string) bool {
	sm, sl := module(src)
	local := strings.TrimPrefix(dep, "gatebeam/")
	dm, dl := module(local + "/_.go")
	if strings.HasPrefix(src, "internal/platform/") && dm != "" {
		return true
	}
	if dm != "" && dl == "module" && !strings.HasPrefix(src, "internal/composition/") {
		return true
	}
	if sm != "" && dm != "" && sm != dm {
		return true
	}
	if sm == "" {
		return false
	}
	if sl == "domain" || sl == "application" {
		if strings.Contains(strings.Split(dep, "/")[0], ".") {
			return true
		}
		// net/netip contains pure address/prefix values and parsing, no network I/O.
		if dep == "net" || (strings.HasPrefix(dep, "net/") && dep != "net/netip") || dep == "os" || strings.HasPrefix(dep, "os/") || dep == "syscall" || dep == "io/ioutil" || dep == "database/sql" || strings.HasPrefix(dep, "crypto/") {
			return true
		}
		if dm != "" {
			return dl != "domain" && !(sl == "application" && dl == "application")
		}
		if strings.HasPrefix(local, "internal/") {
			return sl == "domain" || !strings.HasPrefix(local, "internal/platform/")
		}
	}
	return sl == "transport" && dl == "infrastructure"
}
func check(root string) error {
	graph := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".worktrees" || d.Name() == "experiments" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(path, ".go") || (!strings.HasPrefix(rel, "internal/") && !strings.HasPrefix(rel, "cmd/")) {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		// External test packages exercise real adapters, but do not enter the production import graph.
		if strings.HasSuffix(path, "_test.go") && strings.HasSuffix(f.Name.Name, "_test") {
			return nil
		}
		pkg := "gatebeam/" + filepath.ToSlash(filepath.Dir(rel))
		for _, im := range f.Imports {
			dep, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				return err
			}
			if forbidden(rel, dep) {
				return fmt.Errorf("forbidden import: %s -> %s", rel, dep)
			}
			if strings.HasPrefix(dep, "gatebeam/") {
				graph[pkg] = append(graph[pkg], dep)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	state := map[string]int{}
	var visit func(string) error
	visit = func(n string) error {
		if state[n] == 1 {
			return fmt.Errorf("import cycle: %s", n)
		}
		if state[n] == 2 {
			return nil
		}
		state[n] = 1
		for _, dep := range graph[n] {
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[n] = 2
		return nil
	}
	for n := range graph {
		if err := visit(n); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	if err := check(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
