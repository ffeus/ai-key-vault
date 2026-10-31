package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry 是保险箱里的一条 key。
type Entry struct {
	ID         string   `json:"id"`
	Key        string   `json:"key"`
	Provider   string   `json:"provider"`
	Candidates []string `json:"candidates,omitempty"` // 厂商不确定时的候选，检测后会定下来
	Name       string   `json:"name"`
	Note       string   `json:"note"`
	Expires    string   `json:"expires"` // YYYY-MM-DD，可空
	Source     string   `json:"source"`  // 手动添加 / 扫描到的位置
	CreatedAt  int64    `json:"createdAt"`
	Status     string   `json:"status"`
	Amount     *float64 `json:"amount"`
	Currency   string   `json:"currency"`
	CheckNote  string   `json:"checkNote"`
	CheckedAt  int64    `json:"checkedAt"`
}

type vaultData struct {
	Entries []*Entry `json:"entries"`
}

// 文件格式：明文头 + 加密后的 JSON。主密码不保存，只用来派生加密密钥。
type vaultFile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

const kdfIterations = 600_000

var ErrWrongPassword = errors.New("主密码不对")

type Vault struct {
	mu   sync.Mutex
	path string
	key  []byte // 解锁后才有；锁定时清空
	salt []byte
	data *vaultData
}

func vaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir, _ = os.UserHomeDir()
	}
	if p := os.Getenv("AIKEYVAULT_DIR"); p != "" { // 测试用
		dir = p
	}
	return filepath.Join(dir, "AIKeyVault", "vault.json")
}

func NewVault() *Vault { return &Vault{path: vaultPath()} }

func (v *Vault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

func (v *Vault) Unlocked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.key != nil
}

func deriveKey(password string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iter, 32)
}

func (v *Vault) Create(password string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := os.Stat(v.path); err == nil {
		return errors.New("保险箱已存在")
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	k, err := deriveKey(password, salt, kdfIterations)
	if err != nil {
		return err
	}
	v.key, v.salt, v.data = k, salt, &vaultData{}
	return v.saveLocked()
}

func (v *Vault) Unlock(password string) error {
	raw, err := os.ReadFile(v.path)
	if err != nil {
		return err
	}
	var f vaultFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return errors.New("保险箱文件损坏")
	}
	salt, _ := hex.DecodeString(f.Salt)
	nonce, _ := hex.DecodeString(f.Nonce)
	ct, _ := hex.DecodeString(f.Ciphertext)
	k, err := deriveKey(password, salt, f.Iterations)
	if err != nil {
		return err
	}
	gcm, err := newGCM(k)
	if err != nil {
		return err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return ErrWrongPassword
	}
	var d vaultData
	if err := json.Unmarshal(pt, &d); err != nil {
		return errors.New("保险箱内容损坏")
	}
	v.mu.Lock()
	v.key, v.salt, v.data = k, salt, &d
	v.mu.Unlock()
	return nil
}

func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.key {
		v.key[i] = 0
	}
	v.key, v.data = nil, nil
}

func newGCM(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// saveLocked 调用前必须已持有 v.mu。先写临时文件再改名，避免写一半断电把文件写坏。
func (v *Vault) saveLocked() error {
	if v.key == nil {
		return errors.New("保险箱已锁定")
	}
	pt, _ := json.Marshal(v.data)
	gcm, err := newGCM(v.key)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	f := vaultFile{
		Version: 1, KDF: "pbkdf2-sha256", Iterations: kdfIterations,
		Salt: hex.EncodeToString(v.salt), Nonce: hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(gcm.Seal(nil, nonce, pt, nil)),
	}
	out, _ := json.MarshalIndent(f, "", "  ")
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// With 在锁内读写数据；fn 返回 true 表示有修改，需要保存。
func (v *Vault) With(fn func(d *vaultData) (bool, error)) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return errors.New("保险箱已锁定")
	}
	changed, err := fn(v.data)
	if err != nil {
		return err
	}
	if changed {
		return v.saveLocked()
	}
	return nil
}

func (d *vaultData) find(id string) *Entry {
	for _, e := range d.Entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func (d *vaultData) findKey(key string) *Entry {
	for _, e := range d.Entries {
		if e.Key == key {
			return e
		}
	}
	return nil
}

func (d *vaultData) add(key string, cands []string, name, note, expires, source string) (*Entry, bool) {
	if e := d.findKey(key); e != nil {
		return e, false
	}
	e := &Entry{
		ID: newID(), Key: key, Provider: cands[0], Name: name, Note: note,
		Expires: expires, Source: source, CreatedAt: time.Now().Unix(),
	}
	if len(cands) > 1 {
		e.Candidates = cands
	}
	d.Entries = append(d.Entries, e)
	return e, true
}
