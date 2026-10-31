package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Provider 描述一家 AI 厂商：用来识别 key、复制接口地址、打开控制台、检测余额。
type Provider struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	BaseURL  string   `json:"baseUrl"`
	Console  string   `json:"console"`
	Keywords []string `json:"-"`
}

var providers = []Provider{
	{"deepseek", "DeepSeek", "https://api.deepseek.com", "https://platform.deepseek.com/api_keys", []string{"DEEPSEEK", "api.deepseek.com"}},
	{"moonshot", "Kimi / 月之暗面", "https://api.moonshot.cn/v1", "https://platform.moonshot.cn/console/api-keys", []string{"MOONSHOT", "KIMI", "api.moonshot.cn", "api.moonshot.ai"}},
	{"dashscope", "阿里百炼 / 通义千问", "https://dashscope.aliyuncs.com/compatible-mode/v1", "https://bailian.console.aliyun.com/", []string{"DASHSCOPE", "QWEN", "BAILIAN", "TONGYI", "dashscope.aliyuncs.com"}},
	{"zhipu", "智谱 GLM", "https://open.bigmodel.cn/api/paas/v4", "https://open.bigmodel.cn/usercenter/apikeys", []string{"ZHIPU", "BIGMODEL", "GLM", "open.bigmodel.cn", "api.z.ai"}},
	{"ark", "火山方舟 / 豆包", "https://ark.cn-beijing.volces.com/api/v3", "https://console.volcengine.com/ark", []string{"ARK_API", "DOUBAO", "VOLC", "volces.com"}},
	{"siliconflow", "硅基流动", "https://api.siliconflow.cn/v1", "https://cloud.siliconflow.cn/account/ak", []string{"SILICONFLOW", "siliconflow.cn", "siliconflow.com"}},
	{"minimax", "MiniMax", "https://api.minimaxi.com/v1", "https://platform.minimaxi.com/", []string{"MINIMAX", "minimax.chat", "minimaxi.com"}},
	{"hunyuan", "腾讯混元", "https://api.hunyuan.cloud.tencent.com/v1", "https://console.cloud.tencent.com/hunyuan", []string{"HUNYUAN", "hunyuan.cloud.tencent.com"}},
	{"qianfan", "百度千帆 / 文心", "https://qianfan.baidubce.com/v2", "https://console.bce.baidu.com/qianfan/", []string{"QIANFAN", "ERNIE", "baidubce.com"}},
	{"stepfun", "阶跃星辰", "https://api.stepfun.com/v1", "https://platform.stepfun.com/", []string{"STEPFUN", "STEP_API", "api.stepfun.com"}},
	{"baichuan", "百川", "https://api.baichuan-ai.com/v1", "https://platform.baichuan-ai.com/", []string{"BAICHUAN", "baichuan-ai.com"}},
	{"openai", "OpenAI", "https://api.openai.com/v1", "https://platform.openai.com/api-keys", []string{"OPENAI", "api.openai.com"}},
	{"anthropic", "Anthropic / Claude", "https://api.anthropic.com", "https://console.anthropic.com/settings/keys", []string{"ANTHROPIC", "api.anthropic.com"}},
	{"gemini", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta", "https://aistudio.google.com/apikey", []string{"GEMINI", "GOOGLE_API", "generativelanguage.googleapis.com"}},
	{"openrouter", "OpenRouter", "https://openrouter.ai/api/v1", "https://openrouter.ai/settings/keys", []string{"OPENROUTER", "openrouter.ai"}},
	{"groq", "Groq", "https://api.groq.com/openai/v1", "https://console.groq.com/keys", []string{"GROQ", "api.groq.com"}},
	{"xai", "xAI / Grok", "https://api.x.ai/v1", "https://console.x.ai/", []string{"XAI_API", "GROK", "api.x.ai"}},
	{"unknown", "其他 / 未识别", "", "", nil},
}

func providerByID(id string) Provider {
	for _, p := range providers {
		if p.ID == id {
			return p
		}
	}
	return providers[len(providers)-1]
}

// ───────── 识别 ─────────

type pattern struct {
	re    *regexp.Regexp
	cands []string // nil = 只能靠上下文判断
}

var patterns = []pattern{
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{80,120}`), []string{"anthropic"}},
	{regexp.MustCompile(`sk-or-v1-[0-9a-f]{64}`), []string{"openrouter"}},
	{regexp.MustCompile(`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,200}`), []string{"openai"}},
	{regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), []string{"gemini"}},
	{regexp.MustCompile(`gsk_[A-Za-z0-9]{50,56}`), []string{"groq"}},
	{regexp.MustCompile(`xai-[A-Za-z0-9]{40,90}`), []string{"xai"}},
	{regexp.MustCompile(`bce-v3/ALTAK-[A-Za-z0-9]+/[0-9a-f]{30,50}`), []string{"qianfan"}},
	{regexp.MustCompile(`[0-9a-f]{32}\.[A-Za-z0-9]{16}`), []string{"zhipu"}},
	{regexp.MustCompile(`sk-[a-z]{48}`), []string{"siliconflow"}},
	{regexp.MustCompile(`sk-[0-9a-f]{32}`), []string{"deepseek", "dashscope", "hunyuan", "stepfun"}},
	{regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), []string{"moonshot", "openai", "baichuan"}},
	{regexp.MustCompile(`sk-[A-Za-z0-9]{20,80}`), nil},
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// DetectKey 识别单独粘贴进来的 key（没有上下文），返回候选厂商。
func DetectKey(key string) []string {
	key = strings.TrimSpace(key)
	for _, p := range patterns {
		if loc := p.re.FindStringIndex(key); loc != nil && loc[0] == 0 && loc[1] == len(key) {
			if p.cands == nil {
				return []string{"unknown"}
			}
			return p.cands
		}
	}
	if uuidRe.MatchString(key) {
		return []string{"ark"} // 火山方舟的 key 是 UUID 格式
	}
	return []string{"unknown"}
}

var assignRe = regexp.MustCompile(`(?i)([A-Z_][A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN)[A-Z0-9_]*|"?(?:api[_-]?key|apiKey)"?)\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9_\-\.]{19,200})`)
var placeholderRe = regexp.MustCompile(`(?i)x{4,}|your|example|placeholder|dummy|test_?key|<|\$\{|\*{3,}|replace|changeme`)
var hasDigit = regexp.MustCompile(`[0-9]`)
var hasLetter = regexp.MustCompile(`[A-Za-z]`)

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func boundaryOK(text string, s, e int) bool {
	if s > 0 && isWordChar(text[s-1]) {
		return false
	}
	if e < len(text) && (isWordChar(text[e]) || text[e] == '_' || text[e] == '-') {
		return false
	}
	return true
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// 在 key 前后 400 字符里找厂商关键词（变量名、网址），取离 key 最近的那个
func guessByContext(text string, s, e int, cands []string) string {
	lo, hi := max(s-400, 0), min(e+400, len(text))
	window := strings.ToLower(text[lo:hi])
	center := s - lo
	best, bestDist := "", 1<<30
	for _, p := range providers {
		if cands != nil && !contains(cands, p.ID) {
			continue
		}
		for _, kw := range p.Keywords {
			kwl := strings.ToLower(kw)
			off := 0
			for {
				i := strings.Index(window[off:], kwl)
				if i < 0 {
					break
				}
				pos := off + i
				d := pos - center
				if d < 0 {
					d = -d
				}
				if d < bestDist {
					best, bestDist = p.ID, d
				}
				off = pos + len(kwl)
			}
		}
	}
	return best
}

type hit struct {
	key   string
	provs []string
	sure  bool
	pos   int
}

func classify(text string, s, e int, cands []string) ([]string, bool) {
	if len(cands) == 1 {
		return cands, true
	}
	if h := guessByContext(text, s, e, cands); h != "" {
		return []string{h}, true
	}
	if cands == nil {
		if h := guessByContext(text, s, e, nil); h != "" {
			return []string{h}, true
		}
		return []string{"unknown"}, false
	}
	return cands, false
}

func distinct(s string) int {
	m := map[rune]bool{}
	for _, r := range s {
		m[r] = true
	}
	return len(m)
}

// scanText 从一段文本（文件内容、环境变量）里找出所有 key
func scanText(text string) []hit {
	var out []hit
	var taken [][2]int
	overlaps := func(s, e int) bool {
		for _, t := range taken {
			if s < t[1] && e > t[0] {
				return true
			}
		}
		return false
	}
	for _, p := range patterns {
		for _, m := range p.re.FindAllStringIndex(text, -1) {
			s, e := m[0], m[1]
			k := text[s:e]
			if overlaps(s, e) || !boundaryOK(text, s, e) || placeholderRe.MatchString(k) {
				continue
			}
			taken = append(taken, [2]int{s, e})
			provs, sure := classify(text, s, e, p.cands)
			out = append(out, hit{k, provs, sure, s})
		}
	}
	for _, m := range assignRe.FindAllStringSubmatchIndex(text, -1) {
		s, e := m[4], m[5]
		val := text[s:e]
		name := text[m[2]:m[3]]
		if overlaps(s, e) || placeholderRe.MatchString(val) {
			continue
		}
		if !hasDigit.MatchString(val) || !hasLetter.MatchString(val) || distinct(val) < 8 {
			continue
		}
		taken = append(taken, [2]int{s, e})
		if h := guessByContext(name, 0, 0, nil); h != "" {
			out = append(out, hit{val, []string{h}, true, s})
		} else {
			provs, sure := classify(text, s, e, nil)
			out = append(out, hit{val, provs, sure, s})
		}
	}
	return out
}

// ───────── 联网检测 ─────────

var client = &http.Client{Timeout: 12 * time.Second}

func httpGet(url string, headers map[string]string) (int, map[string]any) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "ai-key-vault/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	var d map[string]any
	if resp.StatusCode < 300 {
		json.NewDecoder(resp.Body).Decode(&d)
	}
	return resp.StatusCode, d
}

func bearer(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} }

const (
	StValid   = "valid"
	StInvalid = "invalid"
	StNetErr  = "neterr"
	StUnsup   = "unsupported"
	StError   = "error"
)

func statusOf(code int) string {
	switch {
	case code == 0:
		return StNetErr
	case code == 401 || code == 403:
		return StInvalid
	case code < 300:
		return StValid
	}
	return StError
}

// CheckResult 一次检测的结果。Amount/Currency 只有能查余额的厂商才有。
type CheckResult struct {
	Status   string
	Amount   *float64
	Currency string
	Note     string
}

func toFloat(v any) *float64 {
	switch x := v.(type) {
	case float64:
		return &x
	case string:
		var f float64
		if _, err := fmt.Sscanf(x, "%f", &f); err == nil {
			return &f
		}
	}
	return nil
}

func checkOne(pid, key string) CheckResult {
	switch pid {
	case "deepseek":
		code, d := httpGet("https://api.deepseek.com/user/balance", bearer(key))
		if infos, ok := d["balance_infos"].([]any); ok && len(infos) > 0 {
			b, _ := infos[0].(map[string]any)
			cur, _ := b["currency"].(string)
			return CheckResult{StValid, toFloat(b["total_balance"]), cur, ""}
		}
		return CheckResult{Status: statusOf(code)}
	case "moonshot":
		code, d := httpGet("https://api.moonshot.cn/v1/users/me/balance", bearer(key))
		if data, ok := d["data"].(map[string]any); ok {
			return CheckResult{StValid, toFloat(data["available_balance"]), "CNY", ""}
		}
		return CheckResult{Status: statusOf(code)}
	case "siliconflow":
		code, d := httpGet("https://api.siliconflow.cn/v1/user/info", bearer(key))
		if data, ok := d["data"].(map[string]any); ok {
			return CheckResult{StValid, toFloat(data["totalBalance"]), "CNY", ""}
		}
		return CheckResult{Status: statusOf(code)}
	case "openrouter":
		code, d := httpGet("https://openrouter.ai/api/v1/credits", bearer(key))
		if data, ok := d["data"].(map[string]any); ok {
			t, _ := data["total_credits"].(float64)
			u, _ := data["total_usage"].(float64)
			left := t - u
			return CheckResult{StValid, &left, "USD", ""}
		}
		return CheckResult{Status: statusOf(code)}
	}
	endpoints := map[string]struct {
		url string
		h   map[string]string
	}{
		"openai":    {"https://api.openai.com/v1/models", bearer(key)},
		"dashscope": {"https://dashscope.aliyuncs.com/compatible-mode/v1/models", bearer(key)},
		"anthropic": {"https://api.anthropic.com/v1/models", map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}},
		"gemini":    {"https://generativelanguage.googleapis.com/v1beta/models", map[string]string{"x-goog-api-key": key}},
		"groq":      {"https://api.groq.com/openai/v1/models", bearer(key)},
		"xai":       {"https://api.x.ai/v1/models", bearer(key)},
		"stepfun":   {"https://api.stepfun.com/v1/models", bearer(key)},
	}
	if ep, ok := endpoints[pid]; ok {
		code, _ := httpGet(ep.url, ep.h)
		r := CheckResult{Status: statusOf(code)}
		if r.Status == StValid {
			r.Note = "余额请到控制台查看"
		}
		return r
	}
	return CheckResult{Status: StUnsup, Note: "这家暂不支持自动检测，请到控制台查看"}
}

// CheckKey 厂商不确定时依次尝试候选厂商，返回检测结果和最终确定的厂商。
func CheckKey(cands []string, key string) (CheckResult, string) {
	last, lastP := CheckResult{Status: StUnsup, Note: "这家暂不支持自动检测，请到控制台查看"}, cands[0]
	for _, p := range cands {
		r := checkOne(p, key)
		if r.Status == StValid {
			return r, p
		}
		if r.Status != StUnsup {
			last, lastP = r, p
		}
	}
	return last, lastP
}
