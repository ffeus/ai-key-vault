package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var skipDirs = map[string]bool{}
var skipExt = map[string]bool{}

func init() {
	for _, d := range []string{
		"node_modules", ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "env", "site-packages",
		".npm", ".nvm", ".cache", ".Trash", ".gradle", ".m2", ".cargo", ".rustup", "target", "dist", "build",
		"Movies", "Music", "Pictures", "Videos", "Parallels", "Containers", "Group Containers", "Caches", "Cache",
		"Code Cache", "GPUCache", "CachedData", "Service Worker", "blob_storage", "MobileSync", "Mail", "Messages",
		"Metadata", "Logs", "Saved Application State", "Developer", "CoreSimulator", "AIKeyVault",
		"Temp", "Packages", "WindowsApps", "INetCache", "CrashDumps", "D3DSCache", "Microsoft", "NVIDIA",
		"Steam", "SteamLibrary", "Epic Games", "Package Cache", "Windows", "Program Files", "Program Files (x86)",
		"ProgramData", "$Recycle.Bin", "System Volume Information", "$WinREAgent", "Recovery", "PerfLogs",
		"msys64", "Intel", "AMD",
	} {
		skipDirs[strings.ToLower(d)] = true
	}
	for _, e := range strings.Fields(`.png .jpg .jpeg .gif .webp .heic .ico .icns .svg .psd .mp4 .mov .mkv .avi
		.mp3 .wav .flac .m4a .zip .gz .tgz .7z .rar .dmg .pkg .iso .pyc .so .dylib .dll .exe .msi .sys .o .a
		.class .jar .woff .woff2 .ttf .otf .pdf .map .lock .wasm .drp .braw .pptx .docx .xlsx .pak .vpk .bundle
		.assets .vhd .vhdx .vmdk .bin .dat .db-wal .blend .fbx .obj .lnk .cab .esd .wim`) {
		skipExt[e] = true
	}
}

const maxFileBytes = 5 << 20

// Found 是扫描到的一个 key（还没导入保险箱）
type Found struct {
	TempID  string   `json:"id"`
	Key     string   `json:"-"`
	Masked  string   `json:"masked"`
	Provs   []string `json:"providers"`
	Sure    bool     `json:"sure"`
	Locs    []string `json:"locations"`
	InVault bool     `json:"inVault"`
}

type Scanner struct {
	mu      sync.Mutex
	Running bool
	Done    bool
	Files   int
	Current string
	found   map[string]*Found
	order   []string
}

type ScanStatus struct {
	Running bool     `json:"running"`
	Done    bool     `json:"done"`
	Files   int      `json:"files"`
	Current string   `json:"current"`
	Results []*Found `json:"results"`
}

func (s *Scanner) Status(inVault func(string) bool) ScanStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := ScanStatus{Running: s.Running, Done: s.Done, Files: s.Files, Current: s.Current}
	for _, k := range s.order {
		f := s.found[k]
		f.InVault = inVault(f.Key)
		st.Results = append(st.Results, f)
	}
	return st
}

func (s *Scanner) Get(tempID string) *Found {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.found {
		if f.TempID == tempID {
			return f
		}
	}
	return nil
}

func (s *Scanner) Start() bool {
	s.mu.Lock()
	if s.Running {
		s.mu.Unlock()
		return false
	}
	s.Running, s.Done, s.Files, s.found, s.order = true, false, 0, map[string]*Found{}, nil
	s.mu.Unlock()
	go s.run()
	return true
}

func (s *Scanner) add(h hit, loc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.found[h.key]
	if !ok {
		f = &Found{TempID: newID(), Key: h.key, Masked: mask(h.key), Provs: h.provs, Sure: h.sure}
		s.found[h.key] = f
		s.order = append(s.order, h.key)
	}
	if h.sure && !f.Sure {
		f.Provs, f.Sure = h.provs, true
	}
	if !contains(f.Locs, loc) && len(f.Locs) < 20 {
		f.Locs = append(f.Locs, loc)
	}
}

func scanRoots() []string {
	home, _ := os.UserHomeDir()
	roots := []string{home}
	if runtime.GOOS == "windows" {
		for c := 'D'; c <= 'Z'; c++ {
			r := string(c) + `:\`
			if st, err := os.Stat(r); err == nil && st.IsDir() {
				roots = append(roots, r)
			}
		}
	}
	return roots
}

func (s *Scanner) run() {
	defer func() {
		s.mu.Lock()
		s.Running, s.Done, s.Current = false, true, ""
		s.mu.Unlock()
	}()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		for _, h := range scanText(kv) {
			s.add(h, "环境变量 "+name)
		}
	}
	home, _ := os.UserHomeDir()
	for _, root := range scanRoots() {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			name := d.Name()
			if d.IsDir() {
				if p == root {
					return nil
				}
				// macOS 的 ~/Library 里只看 Application Support（AI 客户端的配置在这）
				if runtime.GOOS == "darwin" && filepath.Dir(p) == home && name == "Library" {
					s.walk(filepath.Join(p, "Application Support"), home)
					return fs.SkipDir
				}
				if skipDirs[strings.ToLower(name)] || strings.HasSuffix(name, ".app") || strings.HasPrefix(name, "com.apple.") {
					return fs.SkipDir
				}
				return nil
			}
			s.file(p, d, home)
			return nil
		})
	}
}

func (s *Scanner) walk(root, home string) {
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != root && (skipDirs[strings.ToLower(d.Name())] || strings.HasPrefix(d.Name(), "com.apple.")) {
				return fs.SkipDir
			}
			return nil
		}
		s.file(p, d, home)
		return nil
	})
}

func (s *Scanner) file(p string, d fs.DirEntry, home string) {
	if d.Type()&fs.ModeSymlink != 0 || skipExt[strings.ToLower(filepath.Ext(d.Name()))] {
		return
	}
	info, err := d.Info()
	if err != nil || info.Size() > maxFileBytes || info.Size() == 0 {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	loc := p
	if home != "" && strings.HasPrefix(p, home) {
		loc = "~" + p[len(home):]
	}
	s.mu.Lock()
	s.Files++
	s.Current = loc
	s.mu.Unlock()
	text := string(b) // 按字节匹配，SQLite 等二进制文件里的明文 key 也能找到
	for _, h := range scanText(text) {
		line := strings.Count(text[:h.pos], "\n") + 1
		s.add(h, loc+":"+itoa(line))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func mask(k string) string {
	if len(k) > 14 {
		return k[:6] + "…" + k[len(k)-4:]
	}
	if len(k) > 4 {
		return k[:3] + "…"
	}
	return "…"
}
