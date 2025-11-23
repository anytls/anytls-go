package padding

import (
	"anytls/util"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/sagernet/sing/common/atomic"
)

const CheckMark = -1

// Enhanced default scheme with script capabilities
// Supports legacy format (KV) and new Script format
var defaultPaddingScheme = []byte(`stop=8
jitter=0-10
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

type ActionType int

const (
	ActionPad ActionType = iota
	ActionDelay
)

type Action struct {
	Type     ActionType
	Min, Max int64
}

type Rule struct {
	CondPktOp   string // ">", "<", "==", ">=", "<=", ""(always)
	CondPktVal  int
	CondPrevOp  string // ">", "<", "==", ">=", "<=", ""(always)
	CondPrevVal int
	Actions     []Action
}

type PaddingFactory struct {
	// Common
	RawScheme []byte
	Stop      uint32
	Md5       string

	// Legacy
	legacyScheme util.StringMap
	JitterMin    int64
	JitterMax    int64

	// New Script Engine
	IsScript bool
	Rules    []Rule
}

var DefaultPaddingFactory atomic.TypedValue[*PaddingFactory]

func init() {
	UpdatePaddingScheme(defaultPaddingScheme)
}

func UpdatePaddingScheme(rawScheme []byte) bool {
	if p := NewPaddingFactory(rawScheme); p != nil {
		DefaultPaddingFactory.Store(p)
		return true
	}
	return false
}

func NewPaddingFactory(rawScheme []byte) *PaddingFactory {
	p := &PaddingFactory{
		RawScheme: rawScheme,
		Md5:       fmt.Sprintf("%x", md5.Sum(rawScheme)),
	}

	strScheme := string(rawScheme)
	// Simple detection: if it contains "->", assume it's a script
	if strings.Contains(strScheme, "->") {
		p.IsScript = true
		if err := p.parseScript(strScheme); err != nil {
			return nil
		}
	} else {
		// Fallback to legacy parsing
		p.parseLegacy(rawScheme)
	}

	return p
}

// === Logic for Legacy ===

func (p *PaddingFactory) parseLegacy(raw []byte) {
	scheme := util.StringMapFromBytes(raw)
	if len(scheme) == 0 {
		return
	}
	if stop, err := strconv.Atoi(scheme["stop"]); err == nil {
		p.Stop = uint32(stop)
	}
	if jitterStr, ok := scheme["jitter"]; ok {
		min, max := parseRange(jitterStr)
		p.JitterMin, p.JitterMax = min, max
	}
	p.legacyScheme = scheme
}

// === Logic for Script Engine ===

func (p *PaddingFactory) parseScript(script string) error {
	lines := strings.Split(script, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse globals
		if strings.HasPrefix(line, "stop=") {
			val, _ := strconv.Atoi(strings.TrimPrefix(line, "stop="))
			p.Stop = uint32(val)
			continue
		}

		// Parse Rule: "cond -> actions"
		parts := strings.Split(line, "->")
		if len(parts) != 2 {
			continue
		}

		rule := Rule{}
		conditions := strings.Split(parts[0], "&")
		for _, cond := range conditions {
			cond = strings.TrimSpace(cond)
			if strings.HasPrefix(cond, "pkt") {
				rule.CondPktOp, rule.CondPktVal = parseOpVal(cond, "pkt")
			} else if strings.HasPrefix(cond, "prev") {
				rule.CondPrevOp, rule.CondPrevVal = parseOpVal(cond, "prev")
			}
		}

		actionsStr := strings.Split(parts[1], ",")
		for _, actStr := range actionsStr {
			actStr = strings.TrimSpace(actStr)
			if strings.HasPrefix(actStr, "pad(") {
				min, max := parseFuncArgs(actStr)
				rule.Actions = append(rule.Actions, Action{Type: ActionPad, Min: min, Max: max})
			} else if strings.HasPrefix(actStr, "delay(") {
				min, max := parseFuncArgs(actStr)
				rule.Actions = append(rule.Actions, Action{Type: ActionDelay, Min: min, Max: max})
			}
		}
		p.Rules = append(p.Rules, rule)
	}
	return nil
}

// Helper: parse "pkt >= 10" -> (">=", 10)
func parseOpVal(s, key string) (string, int) {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimPrefix(s, key)
	ops := []string{">=", "<=", "==", ">", "<"}
	for _, op := range ops {
		if strings.HasPrefix(s, op) {
			val, _ := strconv.Atoi(strings.TrimPrefix(s, op))
			return op, val
		}
	}
	return "", 0
}

// Helper: parse "pad(10, 20)" -> (10, 20)
func parseFuncArgs(s string) (int64, int64) {
	start := strings.Index(s, "(")
	end := strings.LastIndex(s, ")")
	if start == -1 || end == -1 {
		return 0, 0
	}
	args := strings.Split(s[start+1:end], "-") // Support 10-20 format inside func too
	if len(args) == 1 {
		// check if comma separated
		args = strings.Split(s[start+1:end], ",")
	}

	if len(args) == 1 {
		v, _ := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
		return v, v
	} else if len(args) >= 2 {
		min, _ := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
		max, _ := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
		return min, max
	}
	return 0, 0
}

func parseRange(s string) (int64, int64) {
	parts := strings.Split(s, "-")
	if len(parts) == 2 {
		min, _ := strconv.ParseInt(parts[0], 10, 64)
		max, _ := strconv.ParseInt(parts[1], 10, 64)
		return min, max
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v, v
}

// === Execution ===

// GenerateActions is the new main entry point
func (p *PaddingFactory) GenerateActions(pkt uint32, prevLen int) []Action {
	var actions []Action

	if p.IsScript {
		// Evaluate Rules
		for _, rule := range p.Rules {
			if matchRule(rule, int(pkt), prevLen) {
				actions = append(actions, rule.Actions...)
				// We don't break here, allowing multiple rules to apply (additive)
				// Or break? For now let's say first match wins to simulate switch-case,
				// but usually additive is powerful. Let's do First Match Wins for simplicity
				// of "if-else" logic simulation.
				return actions
			}
		}
	} else {
		// Legacy Logic Adapter
		// 1. Jitter
		if p.JitterMax > 0 {
			actions = append(actions, Action{Type: ActionDelay, Min: p.JitterMin, Max: p.JitterMax})
		}
		// 2. Pad
		sizes := p.legacyGeneratePayloadSizes(pkt)
		for _, size := range sizes {
			actions = append(actions, Action{Type: ActionPad, Min: int64(size), Max: int64(size)})
		}
	}
	return actions
}

func matchRule(r Rule, pkt, prev int) bool {
	if !evalOp(r.CondPktOp, pkt, r.CondPktVal) {
		return false
	}
	if !evalOp(r.CondPrevOp, prev, r.CondPrevVal) {
		return false
	}
	return true
}

func evalOp(op string, val, target int) bool {
	switch op {
	case "":
		return true
	case ">":
		return val > target
	case "<":
		return val < target
	case "==":
		return val == target
	case ">=":
		return val >= target
	case "<=":
		return val <= target
	}
	return false
}

// Legacy generator (private)
func (p *PaddingFactory) legacyGeneratePayloadSizes(pkt uint32) (pktSizes []int) {
	if s, ok := p.legacyScheme[strconv.Itoa(int(pkt))]; ok {
		sRanges := strings.Split(s, ",")
		for _, sRange := range sRanges {
			sRangeMinMax := strings.Split(sRange, "-")
			if len(sRangeMinMax) == 2 {
				_min, _ := strconv.ParseInt(sRangeMinMax[0], 10, 64)
				_max, _ := strconv.ParseInt(sRangeMinMax[1], 10, 64)
				_min, _max = min(_min, _max), max(_min, _max)
				if _min == _max {
					pktSizes = append(pktSizes, int(_min))
				} else {
					i, _ := rand.Int(rand.Reader, big.NewInt(_max-_min))
					pktSizes = append(pktSizes, int(i.Int64()+_min))
				}
			} else if sRange == "c" {
				pktSizes = append(pktSizes, CheckMark)
			}
		}
	}
	return
}

// Keep for compatibility with external calls (e.g. client hello)
func (p *PaddingFactory) GenerateRecordPayloadSizes(pkt uint32) []int {
	// Simulate actions with prevLen=0
	actions := p.GenerateActions(pkt, 0)
	var sizes []int
	for _, act := range actions {
		if act.Type == ActionPad {
			if act.Min == act.Max {
				sizes = append(sizes, int(act.Min))
			} else {
				delta := act.Max - act.Min
				if delta > 0 {
					i, _ := rand.Int(rand.Reader, big.NewInt(delta))
					sizes = append(sizes, int(act.Min+i.Int64()))
				} else {
					sizes = append(sizes, int(act.Min))
				}
			}
		}
	}
	return sizes
}
