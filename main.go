// AI Key 管家：本地管理各家 AI 厂商 API key 的小工具。
//
// 双击运行后会在本机 127.0.0.1 上启动一个只给自己用的网页界面，并自动打开浏览器。
// 所有 key 用主密码加密后保存在本机，不上传到任何服务器；
// 检测余额时，key 只会发给对应厂商的官方接口。
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	preferredPort = 17345
	autoLockAfter = 15 * time.Minute
	version       = "0.1.0"
)

type App struct {
	vault   *Vault
	scanner *Scanner
	token   string
	host    string

	actMu    sync.Mutex
	lastSeen time.Time
}

func main() {
	setupConsole()
	app := &App{vault: NewVault(), scanner: &Scanner{}, lastSeen: time.Now()}

	// 已经在运行就直接打开已有的窗口，避免两个进程同时写一个保险箱
	if url, ok := existingInstance(); ok {
		fmt.Println("AI Key 管家已经在运行，正在打开页面…")
		openBrowser(url)
		time.Sleep(time.Second)
		return
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", preferredPort))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("启动失败：", err)
			waitEnter()
			return
		}
	}
	port := ln.Addr().(*net.TCPAddr).Port
	app.host = fmt.Sprintf("127.0.0.1:%d", port)
	tok := make([]byte, 24)
	rand.Read(tok)
	app.token = hex.EncodeToString(tok)
	url := fmt.Sprintf("http://%s/#t=%s", app.host, app.token)
	writeSession(port, app.token)
	defer removeSession()

	go app.autoLock()

	fmt.Println("==============================================")
	fmt.Println("  AI Key 管家 v" + version)
	fmt.Println("  key 加密保存在本机：" + app.vault.path)
	fmt.Println("==============================================")
	fmt.Println("已在浏览器中打开。如果没有自动打开，请复制下面的地址到浏览器：")
	fmt.Println("  " + url)
	fmt.Println()
	fmt.Println("用完直接关掉这个窗口即可退出。")
	if os.Getenv("AIKEYVAULT_NO_BROWSER") == "" {
		openBrowser(url)
	}
	if err := http.Serve(ln, app.routes()); err != nil {
		fmt.Println("服务出错：", err)
		waitEnter()
	}
}

// ───────── 单实例 ─────────

func sessionPath() string { return filepath.Join(filepath.Dir(vaultPath()), "session.json") }

func writeSession(port int, token string) {
	os.MkdirAll(filepath.Dir(sessionPath()), 0o700)
	b, _ := json.Marshal(map[string]any{"port": port, "token": token, "pid": os.Getpid()})
	os.WriteFile(sessionPath(), b, 0o600)
}

func removeSession() { os.Remove(sessionPath()) }

func existingInstance() (string, bool) {
	b, err := os.ReadFile(sessionPath())
	if err != nil {
		return "", false
	}
	var s struct {
		Port  int    `json:"port"`
		Token string `json:"token"`
	}
	if json.Unmarshal(b, &s) != nil || s.Port == 0 {
		return "", false
	}
	host := fmt.Sprintf("127.0.0.1:%d", s.Port)
	req, _ := http.NewRequest("GET", "http://"+host+"/api/ping", nil)
	req.Header.Set("X-Token", s.Token)
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", false
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", false
	}
	return fmt.Sprintf("http://%s/#t=%s", host, s.Token), true
}

// ───────── 自动锁定 ─────────

func (a *App) touch() {
	a.actMu.Lock()
	a.lastSeen = time.Now()
	a.actMu.Unlock()
}

func (a *App) autoLock() {
	for range time.Tick(30 * time.Second) {
		a.actMu.Lock()
		idle := time.Since(a.lastSeen)
		a.actMu.Unlock()
		if idle > autoLockAfter && a.vault.Unlocked() {
			a.vault.Lock()
			fmt.Println(time.Now().Format("15:04"), "超过 15 分钟没有操作，已自动锁定。")
		}
	}
}

// ───────── 路由与安全 ─────────

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	static := http.FileServer(http.FS(sub))

	mux.HandleFunc("GET /api/ping", a.api(false, func(r *http.Request) (any, error) { return map[string]string{"version": version}, nil }))
	mux.HandleFunc("GET /api/state", a.api(false, a.state))
	mux.HandleFunc("POST /api/setup", a.api(false, a.setup))
	mux.HandleFunc("POST /api/unlock", a.api(false, a.unlock))
	mux.HandleFunc("POST /api/lock", a.api(false, func(r *http.Request) (any, error) { a.vault.Lock(); return ok(), nil }))
	mux.HandleFunc("GET /api/entries", a.api(true, a.listEntries))
	mux.HandleFunc("POST /api/entries", a.api(true, a.addEntry))
	mux.HandleFunc("PUT /api/entries/{id}", a.api(true, a.updateEntry))
	mux.HandleFunc("DELETE /api/entries/{id}", a.api(true, a.deleteEntry))
	mux.HandleFunc("GET /api/entries/{id}/reveal", a.api(true, a.reveal))
	mux.HandleFunc("POST /api/check", a.api(true, a.check))
	mux.HandleFunc("POST /api/detect", a.api(true, a.detect))
	mux.HandleFunc("POST /api/scan/start", a.api(true, a.scanStart))
	mux.HandleFunc("GET /api/scan/status", a.api(true, a.scanStatus))
	mux.HandleFunc("POST /api/scan/import", a.api(true, a.scanImport))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 防 DNS 重绑定：只接受直接访问 127.0.0.1:端口 的请求
		if r.Host != a.host && r.Host != strings.Replace(a.host, "127.0.0.1", "localhost", 1) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// 每个接口都要带启动时随机生成的令牌，别的网页拿不到它，也就调不了这些接口
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(a.token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "令牌无效，请关掉这个页面，重新双击程序打开"})
				return
			}
			mux.ServeHTTP(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
}

type httpErr struct {
	code int
	msg  string
}

func (e httpErr) Error() string { return e.msg }

func ok() map[string]bool { return map[string]bool{"ok": true} }

func (a *App) api(needUnlock bool, fn func(r *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.touch()
		if needUnlock && !a.vault.Unlocked() {
			writeJSON(w, http.StatusLocked, map[string]string{"error": "locked"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		res, err := fn(r)
		if err != nil {
			code := http.StatusBadRequest
			var he httpErr
			if errors.As(err, &he) {
				code = he.code
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.New("请求格式不对")
	}
	return nil
}

// ───────── 主密码 ─────────

func (a *App) state(r *http.Request) (any, error) {
	return map[string]any{
		"exists": a.vault.Exists(), "unlocked": a.vault.Unlocked(),
		"version": version, "path": a.vault.path,
	}, nil
}

func (a *App) setup(r *http.Request) (any, error) {
	var in struct{ Password string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if len([]rune(in.Password)) < 8 {
		return nil, errors.New("主密码至少 8 位")
	}
	if err := a.vault.Create(in.Password); err != nil {
		return nil, err
	}
	return ok(), nil
}

var unlockMu sync.Mutex
var failCount int

func (a *App) unlock(r *http.Request) (any, error) {
	var in struct{ Password string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	unlockMu.Lock()
	defer unlockMu.Unlock()
	if failCount >= 5 { // 连续输错后放慢速度，防止被暴力尝试
		time.Sleep(time.Duration(failCount) * time.Second)
	}
	if err := a.vault.Unlock(in.Password); err != nil {
		if errors.Is(err, ErrWrongPassword) {
			failCount++
		}
		return nil, err
	}
	failCount = 0
	return ok(), nil
}

// ───────── key 增删改查 ─────────

type entryView struct {
	ID           string   `json:"id"`
	Masked       string   `json:"masked"`
	Provider     string   `json:"provider"`
	ProviderName string   `json:"providerName"`
	Candidates   []string `json:"candidates"`
	BaseURL      string   `json:"baseUrl"`
	Console      string   `json:"console"`
	Name         string   `json:"name"`
	Note         string   `json:"note"`
	Expires      string   `json:"expires"`
	Source       string   `json:"source"`
	CreatedAt    int64    `json:"createdAt"`
	Status       string   `json:"status"`
	Amount       *float64 `json:"amount"`
	Currency     string   `json:"currency"`
	CheckNote    string   `json:"checkNote"`
	CheckedAt    int64    `json:"checkedAt"`
}

func view(e *Entry) entryView {
	p := providerByID(e.Provider)
	name := p.Name
	if len(e.Candidates) > 1 {
		ns := make([]string, len(e.Candidates))
		for i, c := range e.Candidates {
			ns[i] = providerByID(c).Name
		}
		name = strings.Join(ns, " 或 ")
	}
	return entryView{
		ID: e.ID, Masked: mask(e.Key), Provider: e.Provider, ProviderName: name, Candidates: e.Candidates,
		BaseURL: p.BaseURL, Console: p.Console, Name: e.Name, Note: e.Note, Expires: e.Expires,
		Source: e.Source, CreatedAt: e.CreatedAt, Status: e.Status, Amount: e.Amount,
		Currency: e.Currency, CheckNote: e.CheckNote, CheckedAt: e.CheckedAt,
	}
}

func (a *App) listEntries(r *http.Request) (any, error) {
	var out []entryView
	err := a.vault.With(func(d *vaultData) (bool, error) {
		for _, e := range d.Entries {
			out = append(out, view(e))
		}
		return false, nil
	})
	if out == nil {
		out = []entryView{}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return map[string]any{"entries": out, "providers": providers}, err
}

type entryInput struct {
	Key      string `json:"key"`
	Provider string `json:"provider"` // 空 = 自动识别
	Name     string `json:"name"`
	Note     string `json:"note"`
	Expires  string `json:"expires"`
}

func validExpires(s string) bool {
	if s == "" {
		return true
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

func (a *App) addEntry(r *http.Request) (any, error) {
	var in entryInput
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Key = strings.TrimSpace(in.Key)
	in.Key = strings.Trim(in.Key, `"'`)
	if len(in.Key) < 16 || strings.ContainsAny(in.Key, " \t\r\n") {
		return nil, errors.New("这看起来不像一个 API key，请检查是否完整复制")
	}
	if !validExpires(in.Expires) {
		return nil, errors.New("到期日期格式不对")
	}
	cands := DetectKey(in.Key)
	if in.Provider != "" {
		cands = []string{providerByID(in.Provider).ID}
	}
	var res entryView
	var created bool
	err := a.vault.With(func(d *vaultData) (bool, error) {
		e, isNew := d.add(in.Key, cands, strings.TrimSpace(in.Name), strings.TrimSpace(in.Note), in.Expires, "手动添加")
		res, created = view(e), isNew
		return isNew, nil
	})
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, errors.New("这个 key 已经存在了：" + res.ProviderName + " " + res.Masked)
	}
	return res, nil
}

func (a *App) updateEntry(r *http.Request) (any, error) {
	var in entryInput
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if !validExpires(in.Expires) {
		return nil, errors.New("到期日期格式不对")
	}
	id := r.PathValue("id")
	var res entryView
	err := a.vault.With(func(d *vaultData) (bool, error) {
		e := d.find(id)
		if e == nil {
			return false, httpErr{404, "找不到这个 key"}
		}
		if in.Provider != "" && in.Provider != e.Provider {
			e.Provider, e.Candidates = providerByID(in.Provider).ID, nil
			e.Status, e.Amount, e.Currency, e.CheckNote, e.CheckedAt = "", nil, "", "", 0
		}
		e.Name, e.Note, e.Expires = strings.TrimSpace(in.Name), strings.TrimSpace(in.Note), in.Expires
		res = view(e)
		return true, nil
	})
	return res, err
}

func (a *App) deleteEntry(r *http.Request) (any, error) {
	id := r.PathValue("id")
	err := a.vault.With(func(d *vaultData) (bool, error) {
		for i, e := range d.Entries {
			if e.ID == id {
				d.Entries = append(d.Entries[:i], d.Entries[i+1:]...)
				return true, nil
			}
		}
		return false, httpErr{404, "找不到这个 key"}
	})
	return ok(), err
}

func (a *App) reveal(r *http.Request) (any, error) {
	id := r.PathValue("id")
	var key string
	err := a.vault.With(func(d *vaultData) (bool, error) {
		e := d.find(id)
		if e == nil {
			return false, httpErr{404, "找不到这个 key"}
		}
		key = e.Key
		return false, nil
	})
	return map[string]string{"key": key}, err
}

func (a *App) detect(r *http.Request) (any, error) {
	var in struct{ Key string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c := DetectKey(strings.Trim(strings.TrimSpace(in.Key), `"'`))
	return map[string]any{"candidates": c}, nil
}

// ───────── 检测 ─────────

func (a *App) check(r *http.Request) (any, error) {
	var in struct {
		IDs []string `json:"ids"` // 空 = 全部
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	type job struct {
		id, key string
		cands   []string
	}
	var jobs []job
	err := a.vault.With(func(d *vaultData) (bool, error) {
		for _, e := range d.Entries {
			if len(in.IDs) == 0 || contains(in.IDs, e.ID) {
				c := e.Candidates
				if len(c) == 0 {
					c = []string{e.Provider}
				}
				jobs = append(jobs, job{e.ID, e.Key, c})
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	type result struct {
		id  string
		r   CheckResult
		pid string
	}
	results := make(chan result, len(jobs))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r, pid := CheckKey(j.cands, j.key)
			results <- result{j.id, r, pid}
		}(j)
	}
	wg.Wait()
	close(results)

	now := time.Now().Unix()
	err = a.vault.With(func(d *vaultData) (bool, error) {
		for res := range results {
			e := d.find(res.id)
			if e == nil {
				continue
			}
			e.Status, e.Amount, e.Currency, e.CheckNote, e.CheckedAt = res.r.Status, res.r.Amount, res.r.Currency, res.r.Note, now
			if res.r.Status == StValid && len(e.Candidates) > 1 {
				e.Provider, e.Candidates = res.pid, nil // 检测成功就能确定是哪家的
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return a.listEntries(r)
}

// ───────── 扫描导入 ─────────

func (a *App) scanStart(r *http.Request) (any, error) {
	a.scanner.Start()
	return ok(), nil
}

func (a *App) inVaultFn() func(string) bool {
	keys := map[string]bool{}
	a.vault.With(func(d *vaultData) (bool, error) {
		for _, e := range d.Entries {
			keys[e.Key] = true
		}
		return false, nil
	})
	return func(k string) bool { return keys[k] }
}

func (a *App) scanStatus(r *http.Request) (any, error) {
	st := a.scanner.Status(a.inVaultFn())
	if st.Results == nil {
		st.Results = []*Found{}
	}
	return st, nil
}

func (a *App) scanImport(r *http.Request) (any, error) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	n := 0
	err := a.vault.With(func(d *vaultData) (bool, error) {
		for _, id := range in.IDs {
			f := a.scanner.Get(id)
			if f == nil {
				continue
			}
			src := "扫描导入：" + f.Locs[0]
			if len(f.Locs) > 1 {
				src += fmt.Sprintf(" 等 %d 处", len(f.Locs))
			}
			if _, isNew := d.add(f.Key, f.Provs, "", "", "", src); isNew {
				n++
			}
		}
		return n > 0, nil
	})
	return map[string]int{"imported": n}, err
}

// ───────── 其他 ─────────

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}

func waitEnter() {
	fmt.Println("按回车键关闭…")
	var s string
	fmt.Scanln(&s)
}
