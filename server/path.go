// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	maxEncodingLevels      = 3
	maxPathInterpretations = 256
)

var (
	errInvalidPercentEscape       = errors.New("invalid percent-encoding in request path")
	errControlCharInPath          = errors.New("control character in request path")
	errTooManyEncodingLevels      = errors.New("request path exceeds maximum percent-encoding depth")
	errTooManyPathInterpretations = errors.New("request path produces too many interpretations")
)

// expandPathInterpretations expands rawPath into every path interpretation an
// upstream server or proxy might resolve it to (full, unreserved-only, and
// slash-preserving percent-decoding; overlong UTF-8 folding; NFKC; query and
// fragment truncation; backslash folding; matrix ';' parameter stripping;
// segment trailing-space trimming; slash merging; and RFC 3986 dot-segment
// removal preserving trailing slashes).
//
// It returns an error if the path cannot be interpreted safely (invalid escapes,
// control characters, more than 3 encoding levels, or more than 256 distinct
// interpretations).
func expandPathInterpretations(rawPath string) ([]string, error) {
	if hasControlChar(rawPath) {
		return nil, errControlCharInPath
	}
	if err := validatePercentEscapes(rawPath); err != nil {
		return nil, err
	}

	type decodeState struct {
		path  string
		depth int
	}

	seen := make(map[string]struct{}, 16)
	minDepth := make(map[string]int, 16)
	var ordered []string
	var decodeQueue []decodeState

	addDecoded := func(p string, depth int) error {
		if hasControlChar(p) {
			return errControlCharInPath
		}
		if prevDepth, ok := minDepth[p]; ok {
			if depth < prevDepth {
				minDepth[p] = depth
				decodeQueue = append(decodeQueue, decodeState{path: p, depth: depth})
			}
			return nil
		}
		if len(seen) >= maxPathInterpretations {
			return errTooManyPathInterpretations
		}
		seen[p] = struct{}{}
		minDepth[p] = depth
		ordered = append(ordered, p)
		decodeQueue = append(decodeQueue, decodeState{path: p, depth: depth})
		return nil
	}

	if err := addDecoded(rawPath, 0); err != nil {
		return nil, err
	}

	// Phase A: decoding expansion with bounded percent-encoding depth.
	for head := 0; head < len(decodeQueue); head++ {
		cur := decodeQueue[head]

		decoders := []func(string) (string, bool){
			decodePercentAll,
			decodePercentUnreserved,
			decodePercentKeepSlashes,
		}
		for _, fn := range decoders {
			if next, changed := fn(cur.path); changed {
				if cur.depth >= maxEncodingLevels {
					return nil, errTooManyEncodingLevels
				}
				if err := addDecoded(next, cur.depth+1); err != nil {
					return nil, err
				}
			}
		}

		if folded, changed := foldOverlongUTF8(cur.path); changed {
			if err := addDecoded(folded, cur.depth); err != nil {
				return nil, err
			}
		}

		if nfkc := norm.NFKC.String(cur.path); nfkc != cur.path {
			if err := addDecoded(nfkc, cur.depth); err != nil {
				return nil, err
			}
		}
	}

	// Phase B: structural normalization closure across all decoded variants.
	addNormalized := func(p string) error {
		if hasControlChar(p) {
			return errControlCharInPath
		}
		if _, ok := seen[p]; ok {
			return nil
		}
		if len(seen) >= maxPathInterpretations {
			return errTooManyPathInterpretations
		}
		seen[p] = struct{}{}
		ordered = append(ordered, p)
		return nil
	}

	for head := 0; head < len(ordered); head++ {
		p := ordered[head]

		if idx := strings.IndexByte(p, '?'); idx >= 0 {
			if err := addNormalized(p[:idx]); err != nil {
				return nil, err
			}
		}
		if idx := strings.IndexByte(p, '#'); idx >= 0 {
			if err := addNormalized(p[:idx]); err != nil {
				return nil, err
			}
		}
		if strings.ContainsRune(p, '\\') {
			if err := addNormalized(strings.ReplaceAll(p, "\\", "/")); err != nil {
				return nil, err
			}
		}
		if stripped := stripMatrixParams(p); stripped != p {
			if err := addNormalized(stripped); err != nil {
				return nil, err
			}
		}
		if trimmed := trimSegmentTrailingSpaces(p); trimmed != p {
			if err := addNormalized(trimmed); err != nil {
				return nil, err
			}
		}
		if merged := mergeSlashes(p); merged != p {
			if err := addNormalized(merged); err != nil {
				return nil, err
			}
		}
		if cleaned := removeDotSegments(p); cleaned != p {
			if err := addNormalized(cleaned); err != nil {
				return nil, err
			}
		}
		if folded, changed := foldOverlongUTF8(p); changed {
			if err := addNormalized(folded); err != nil {
				return nil, err
			}
		}
		if nfkc := norm.NFKC.String(p); nfkc != p {
			if err := addNormalized(nfkc); err != nil {
				return nil, err
			}
		}
	}

	return ordered, nil
}

func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	for _, r := range s {
		if r != utf8.RuneError && unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func fromHex(b byte) (byte, bool) {
	switch {
	case '0' <= b && b <= '9':
		return b - '0', true
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10, true
	case 'A' <= b && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func validatePercentEscapes(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+2 >= len(s) {
			return errInvalidPercentEscape
		}
		if _, ok := fromHex(s[i+1]); !ok {
			return errInvalidPercentEscape
		}
		if _, ok := fromHex(s[i+2]); !ok {
			return errInvalidPercentEscape
		}
		i += 2
	}
	return nil
}

func isUnreservedByte(b byte) bool {
	return ('A' <= b && b <= 'Z') ||
		('a' <= b && b <= 'z') ||
		('0' <= b && b <= '9') ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

func decodePercentFiltered(s string, allow func(byte) bool) (string, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := fromHex(s[i+1])
			lo, ok2 := fromHex(s[i+2])
			if ok1 && ok2 {
				decoded := (hi << 4) | lo
				if allow(decoded) {
					if !changed {
						b.Grow(len(s))
						b.WriteString(s[:i])
						changed = true
					}
					b.WriteByte(decoded)
					i += 2
					continue
				}
			}
		}
		if changed {
			b.WriteByte(s[i])
		}
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func decodePercentAll(s string) (string, bool) {
	return decodePercentFiltered(s, func(byte) bool { return true })
}

func decodePercentUnreserved(s string) (string, bool) {
	return decodePercentFiltered(s, isUnreservedByte)
}

func decodePercentKeepSlashes(s string) (string, bool) {
	return decodePercentFiltered(s, func(b byte) bool {
		return b != '/' && b != '\\'
	})
}

// foldOverlongUTF8 decodes overlong 2-, 3-, and 4-byte UTF-8 sequences back to
// their underlying code points so traversal characters like %C0%AE (.) or
// %C0%AF (/) cannot hide behind invalid UTF-8 encodings.
func foldOverlongUTF8(s string) (string, bool) {
	var b strings.Builder
	changed := false
	n := len(s)
	for i := 0; i < n; {
		b0 := s[i]
		// 2-byte overlong: 110xxxxx 10xxxxxx with cp < 0x80
		if b0 >= 0xC0 && b0 <= 0xDF && i+1 < n && (s[i+1]&0xC0) == 0x80 {
			cp := rune(b0&0x1F)<<6 | rune(s[i+1]&0x3F)
			if cp < 0x80 {
				if !changed {
					b.Grow(n)
					b.WriteString(s[:i])
					changed = true
				}
				b.WriteRune(cp)
				i += 2
				continue
			}
		}
		// 3-byte overlong: 1110xxxx 10xxxxxx 10xxxxxx with cp < 0x800
		if b0 >= 0xE0 && b0 <= 0xEF && i+2 < n && (s[i+1]&0xC0) == 0x80 && (s[i+2]&0xC0) == 0x80 {
			cp := rune(b0&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F)
			if cp < 0x800 {
				if !changed {
					b.Grow(n)
					b.WriteString(s[:i])
					changed = true
				}
				b.WriteRune(cp)
				i += 3
				continue
			}
		}
		// 4-byte overlong: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx with cp < 0x10000
		if b0 >= 0xF0 && b0 <= 0xF7 && i+3 < n && (s[i+1]&0xC0) == 0x80 && (s[i+2]&0xC0) == 0x80 && (s[i+3]&0xC0) == 0x80 {
			cp := rune(b0&0x07)<<18 | rune(s[i+1]&0x3F)<<12 | rune(s[i+2]&0x3F)<<6 | rune(s[i+3]&0x3F)
			if cp < 0x10000 && (cp < 0xD800 || cp > 0xDFFF) {
				if !changed {
					b.Grow(n)
					b.WriteString(s[:i])
					changed = true
				}
				b.WriteRune(cp)
				i += 4
				continue
			}
		}
		if changed {
			b.WriteByte(b0)
		}
		i++
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func stripMatrixParams(p string) string {
	if !strings.ContainsRune(p, ';') {
		return p
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if idx := strings.IndexByte(seg, ';'); idx >= 0 {
			segs[i] = seg[:idx]
		}
	}
	return strings.Join(segs, "/")
}

func trimSegmentTrailingSpaces(p string) string {
	if !strings.ContainsRune(p, ' ') {
		return p
	}
	segs := strings.Split(p, "/")
	changed := false
	for i, seg := range segs {
		trimmed := strings.TrimRight(seg, " ")
		if trimmed != seg {
			segs[i] = trimmed
			changed = true
		}
	}
	if !changed {
		return p
	}
	return strings.Join(segs, "/")
}

func mergeSlashes(p string) string {
	if !strings.Contains(p, "//") {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	prevSlash := false
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			if !prevSlash {
				b.WriteByte('/')
				prevSlash = true
			}
			continue
		}
		prevSlash = false
		b.WriteByte(p[i])
	}
	return b.String()
}

// removeDotSegments resolves "." and ".." path segments per RFC 3986 §5.2.4
// while preserving trailing slashes (so "/public/" remains "/public/").
func removeDotSegments(p string) string {
	if p == "" {
		return ""
	}
	leadingSlash := strings.HasPrefix(p, "/")
	trailingSlash := strings.HasSuffix(p, "/")
	segs := strings.Split(p, "/")
	if n := len(segs); n > 0 && (segs[n-1] == "." || segs[n-1] == "..") {
		trailingSlash = true
	}

	stack := make([]string, 0, len(segs))
	for _, seg := range segs {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, seg)
		}
	}

	res := strings.Join(stack, "/")
	if leadingSlash {
		res = "/" + res
	}
	if trailingSlash && res != "/" && res != "" && !strings.HasSuffix(res, "/") {
		res += "/"
	}
	if res == "" && leadingSlash {
		res = "/"
	}
	return res
}
