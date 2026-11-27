package fingerprints

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	defaultWinnowK          = 25
	defaultWinnowW          = 15
	defaultMinWinnowMatches = 2
)

// WinnowToken is a single lexically normalized token with its 1-based source line number.
type WinnowToken struct {
	Kind string
	Line int
}

// WinnowFingerprint is a selected L2 Winnowing k-gram hash with source span metadata.
type WinnowFingerprint struct {
	HashHex    string
	LineStart  int
	LineEnd    int
	TokenCount int
}

// DetectLanguage maps a file path (stripping virtual L4 suffixes like #b64[0] or !entry)
// to a normalized language lexer profile. Returns "" for known binary extensions or files with NUL bytes in prefix.
func DetectLanguage(relPath string, data []byte) string {
	if looksBinary(data) {
		return ""
	}
	cleanPath := relPath
	if idx := strings.IndexByte(cleanPath, '#'); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}
	if bang := strings.LastIndexByte(cleanPath, '!'); bang >= 0 {
		cleanPath = cleanPath[bang+1:]
	}
	ext := strings.ToLower(filepath.Ext(cleanPath))
	switch ext {
	case ".go":
		return "go"
	case ".py", ".pyw":
		return "python"
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return "js"
	case ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java", ".rs", ".cs", ".kt", ".kts", ".swift", ".scala":
		return "c_family"
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".pdf", ".zip", ".tar", ".gz", ".tgz", ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".wasm", ".woff", ".woff2":
		if strings.ContainsRune(relPath, '#') || hasHighPrintableAscii(data) || utf8.Valid(data) {
			if inferred := inferLanguageFromContent(data); inferred != "" {
				return inferred
			}
			return "generic"
		}
		return ""
	case ".txt", "":
		if inferred := inferLanguageFromContent(data); inferred != "" {
			return inferred
		}
		return "generic"
	default:
		if inferred := inferLanguageFromContent(data); inferred != "" {
			return inferred
		}
		return "generic"
	}
}

func inferLanguageFromContent(data []byte) string {
	norm := normalizeText(data)
	if strings.Contains(norm, "\npackage ") || strings.HasPrefix(strings.TrimSpace(norm), "package ") {
		if strings.Contains(norm, "\nfunc ") || strings.Contains(norm, "\nimport ") || strings.Contains(norm, ":=") {
			return "go"
		}
	}
	if strings.Contains(norm, "\nfunc ") && (strings.Contains(norm, ":=") || strings.Contains(norm, "float64") || strings.Contains(norm, "uint64") || strings.Contains(norm, "[]byte")) {
		return "go"
	}
	if strings.HasPrefix(norm, "#!/usr/bin/env python") || strings.HasPrefix(norm, "#!/usr/bin/python") ||
		(strings.Contains(norm, "\ndef ") && (strings.Contains(norm, ":\n") || strings.Contains(norm, "\nimport ") || strings.Contains(norm, "\nfrom "))) {
		return "python"
	}
	if (strings.Contains(norm, ":\n    ") || strings.Contains(norm, ":\n\t")) && !strings.Contains(norm, "{\n") &&
		(strings.Contains(norm, "raise ") || strings.Contains(norm, "\nelif ") || strings.Contains(norm, `"""`) || strings.Contains(norm, "enumerate(")) {
		return "python"
	}
	if strings.Contains(norm, "\nfunction ") || strings.Contains(norm, "\nexport ") || strings.Contains(norm, "=> {") {
		return "js"
	}
	if strings.Contains(norm, "#include <") || strings.Contains(norm, `#include "`) || strings.Contains(norm, "\nfn ") {
		return "c_family"
	}
	return ""
}

// ExtractL2Winnow extracts deterministic Winnowing k-gram fingerprints for normalized code.
func ExtractL2Winnow(relPath string, data []byte, k, w int) (string, []WinnowFingerprint) {
	if k <= 0 {
		k = defaultWinnowK
	}
	if w <= 0 {
		w = defaultWinnowW
	}
	lang := DetectLanguage(relPath, data)
	if lang == "" {
		return "", nil
	}
	tokens := TokenizeForWinnow(lang, data)
	if len(tokens) < k {
		return lang, nil
	}
	return lang, WinnowTokens(tokens, k, w)
}

// WinnowTokens computes k-gram hashes and applies rightmost tie-break Winnowing over tokens.
func WinnowTokens(tokens []WinnowToken, k, w int) []WinnowFingerprint {
	if k <= 0 {
		k = defaultWinnowK
	}
	if w <= 0 {
		w = defaultWinnowW
	}
	if len(tokens) < k {
		return nil
	}
	numKGrams := len(tokens) - k + 1
	hashes := make([]uint64, numKGrams)
	for i := 0; i < numKGrams; i++ {
		hashes[i] = hashKGram(tokens[i : i+k])
	}

	emit := func(idx int, out []WinnowFingerprint) []WinnowFingerprint {
		kg := tokens[idx : idx+k]
		if isBoilerplateKGram(kg) {
			return out
		}
		return append(out, WinnowFingerprint{
			HashHex:    fmt.Sprintf("%016x", hashes[idx]),
			LineStart:  kg[0].Line,
			LineEnd:    kg[len(kg)-1].Line,
			TokenCount: k,
		})
	}

	if numKGrams < w {
		minIdx := 0
		for i := 1; i < numKGrams; i++ {
			if hashes[i] <= hashes[minIdx] {
				minIdx = i
			}
		}
		return emit(minIdx, make([]WinnowFingerprint, 0, 1))
	}

	out := make([]WinnowFingerprint, 0, numKGrams/w+4)
	lastEmitted := -1
	for start := 0; start <= numKGrams-w; start++ {
		minIdx := start
		for i := start + 1; i < start+w; i++ {
			if hashes[i] <= hashes[minIdx] {
				minIdx = i
			}
		}
		if minIdx != lastEmitted {
			lastEmitted = minIdx
			out = emit(minIdx, out)
		}
	}
	return out
}

func hashKGram(kg []WinnowToken) uint64 {
	var b strings.Builder
	b.Grow(len(kg) * 5)
	for i, tok := range kg {
		if i > 0 {
			b.WriteByte(0)
		}
		b.WriteString(tok.Kind)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return binary.BigEndian.Uint64(sum[:8])
}

func isBoilerplateKGram(kg []WinnowToken) bool {
	if len(kg) == 0 {
		return true
	}
	distinct := make(map[string]struct{}, 12)
	trivial := 0
	for _, tok := range kg {
		distinct[tok.Kind] = struct{}{}
		switch tok.Kind {
		case "STR", "NUM", ",", ";":
			trivial++
		}
	}
	if len(distinct) < 3 {
		return true
	}
	return trivial*100 >= 85*len(kg)
}

// TokenizeForWinnow lexes source text, strips comments and import preambles,
// and normalizes identifiers, strings, and numbers while preserving keywords and operators.
func TokenizeForWinnow(lang string, data []byte) []WinnowToken {
	s := normalizeText(data)
	kwSet := keywordsForLanguage(lang)
	tokens := make([]WinnowToken, 0, len(s)/6+8)

	line := 1
	n := len(s)
	i := 0
	for i < n {
		c := s[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		if c == ' ' || c == '\t' || c == '\v' || c == '\f' {
			i++
			continue
		}

		// Line comments
		if (lang == "go" || lang == "js" || lang == "c_family" || lang == "generic") &&
			c == '/' && i+1 < n && s[i+1] == '/' {
			i += 2
			for i < n && s[i] != '\n' {
				i++
			}
			continue
		}
		if (lang == "python" || lang == "generic") && c == '#' {
			// In c_family, preserve #include directive token for import preamble stripper.
			i++
			for i < n && s[i] != '\n' {
				i++
			}
			continue
		}
		if lang == "c_family" && c == '#' {
			// Check for #include so preamble exclusion catches it.
			if strings.HasPrefix(s[i:], "#include") {
				tokens = append(tokens, WinnowToken{Kind: "#include", Line: line})
				i += len("#include")
				continue
			}
		}

		// Block comments /* ... */
		if (lang == "go" || lang == "js" || lang == "c_family" || lang == "generic") &&
			c == '/' && i+1 < n && s[i+1] == '*' {
			i += 2
			for i < n {
				if s[i] == '\n' {
					line++
				}
				if s[i] == '*' && i+1 < n && s[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		// Python triple-quoted strings / docstrings
		if lang == "python" && i+2 < n && ((s[i] == '"' && s[i+1] == '"' && s[i+2] == '"') || (s[i] == '\'' && s[i+1] == '\'' && s[i+2] == '\'')) {
			quote := s[i : i+3]
			startLine := line
			isDocstring := len(tokens) == 0 || tokens[len(tokens)-1].Kind == ":" || tokens[len(tokens)-1].Line < line
			i += 3
			for i < n {
				if s[i] == '\\' && i+1 < n {
					if s[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if s[i] == '\n' {
					line++
				}
				if i+2 < n && s[i:i+3] == quote {
					i += 3
					break
				}
				i++
			}
			if isDocstring {
				// Confirm trailing whitespace/newline so assignment like `"""a""" + b` isn't misclassified.
				j := i
				for j < n && (s[j] == ' ' || s[j] == '\t') {
					j++
				}
				if j >= n || s[j] == '\n' || s[j] == '#' {
					continue
				}
			}
			tokens = append(tokens, WinnowToken{Kind: "STR", Line: startLine})
			continue
		}

		// Raw backtick literals (Go no-escape, JS template literal with escape)
		if c == '`' && (lang == "go" || lang == "js" || lang == "generic") {
			startLine := line
			i++
			for i < n {
				if lang != "go" && s[i] == '\\' && i+1 < n {
					if s[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if s[i] == '\n' {
					line++
				}
				if s[i] == '`' {
					i++
					break
				}
				i++
			}
			tokens = append(tokens, WinnowToken{Kind: "STR", Line: startLine})
			continue
		}

		// Quoted string/char literals
		if c == '"' || c == '\'' {
			delim := c
			startLine := line
			i++
			for i < n {
				if s[i] == '\\' && i+1 < n {
					if s[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if s[i] == '\n' {
					line++
					break
				}
				if s[i] == delim {
					i++
					break
				}
				i++
			}
			tokens = append(tokens, WinnowToken{Kind: "STR", Line: startLine})
			continue
		}

		// Numeric literals
		if isASCIIAlphaNumDigit(c) || (c == '.' && i+1 < n && isASCIIAlphaNumDigit(s[i+1])) {
			startLine := line
			i = scanNumber(s, i)
			tokens = append(tokens, WinnowToken{Kind: "NUM", Line: startLine})
			continue
		}

		// Identifiers & keywords (including Python r"..." / f"..." / b"..." string prefixes)
		if isIdentStartByte(c) {
			start := i
			i++
			for i < n && isIdentContByte(s[i]) {
				i++
			}
			word := s[start:i]
			if lang == "python" && i < n && (s[i] == '"' || s[i] == '\'') && isPythonStringPrefix(word) {
				// Let the next iteration consume the string literal as STR without emitting prefix ID.
				continue
			}
			if _, isKW := kwSet[word]; isKW {
				tokens = append(tokens, WinnowToken{Kind: word, Line: line})
			} else {
				tokens = append(tokens, WinnowToken{Kind: "ID", Line: line})
			}
			continue
		}

		// Multi-char operators
		if op, adv := matchMultiCharOp(s[i:]); adv > 0 {
			tokens = append(tokens, WinnowToken{Kind: op, Line: line})
			i += adv
			continue
		}

		// Single-char punctuation / operator
		tokens = append(tokens, WinnowToken{Kind: s[i : i+1], Line: line})
		i++
	}

	return stripImportPreamble(lang, tokens)
}

func isASCIIAlphaNumDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isIdentStartByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (c >= 0x80 && unicode.IsLetter(rune(c)))
}

func isIdentContByte(c byte) bool {
	return isIdentStartByte(c) || isASCIIAlphaNumDigit(c)
}

func isPythonStringPrefix(w string) bool {
	switch strings.ToLower(w) {
	case "r", "f", "b", "u", "rf", "fr", "rb", "br":
		return true
	default:
		return false
	}
}

func scanNumber(s string, i int) int {
	n := len(s)
	if s[i] == '0' && i+1 < n && (s[i+1] == 'x' || s[i+1] == 'X' || s[i+1] == 'b' || s[i+1] == 'B' || s[i+1] == 'o' || s[i+1] == 'O') {
		i += 2
		for i < n && (isASCIIAlphaNumDigit(s[i]) || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F') || s[i] == '_') {
			i++
		}
		return i
	}
	for i < n && (isASCIIAlphaNumDigit(s[i]) || s[i] == '_') {
		i++
	}
	if i < n && s[i] == '.' && i+1 < n && isASCIIAlphaNumDigit(s[i+1]) {
		i++
		for i < n && (isASCIIAlphaNumDigit(s[i]) || s[i] == '_') {
			i++
		}
	}
	if i < n && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < n && (s[j] == '+' || s[j] == '-') {
			j++
		}
		if j < n && isASCIIAlphaNumDigit(s[j]) {
			i = j
			for i < n && (isASCIIAlphaNumDigit(s[i]) || s[i] == '_') {
				i++
			}
		}
	}
	return i
}

func matchMultiCharOp(rem string) (string, int) {
	if len(rem) >= 3 {
		switch rem[:3] {
		case "...", "<<=", ">>=", "===", "!==":
			return rem[:3], 3
		}
	}
	if len(rem) >= 2 {
		switch rem[:2] {
		case ":=", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "++", "--", "->", "=>", "::", "**", "<-", "&^":
			return rem[:2], 2
		}
	}
	return "", 0
}

func stripImportPreamble(lang string, tokens []WinnowToken) []WinnowToken {
	if len(tokens) == 0 {
		return tokens
	}
	out := make([]WinnowToken, 0, len(tokens))
	i := 0
	for i < len(tokens) {
		atLineStart := i == 0 || tokens[i].Line > tokens[i-1].Line || tokens[i-1].Kind == ";"
		tok := tokens[i]

		switch lang {
		case "go":
			if tok.Kind == "import" && atLineStart && i+1 < len(tokens) {
				if tokens[i+1].Kind == "(" {
					depth := 0
					j := i + 1
					for j < len(tokens) {
						if tokens[j].Kind == "(" {
							depth++
						} else if tokens[j].Kind == ")" {
							depth--
							if depth == 0 {
								j++
								break
							}
						}
						j++
					}
					if j < len(tokens) && tokens[j].Kind == ";" {
						j++
					}
					i = j
					continue
				}
				if tokens[i+1].Kind == "STR" {
					i += 2
					if i < len(tokens) && tokens[i].Kind == ";" {
						i++
					}
					continue
				}
				if i+2 < len(tokens) && (tokens[i+1].Kind == "ID" || tokens[i+1].Kind == ".") && tokens[i+2].Kind == "STR" {
					i += 3
					if i < len(tokens) && tokens[i].Kind == ";" {
						i++
					}
					continue
				}
			}
		case "python":
			if atLineStart && (tok.Kind == "import" || (tok.Kind == "from" && hasImportOnStatement(tokens, i))) {
				i = skipPythonImportStmt(tokens, i)
				continue
			}
		case "js":
			if atLineStart && tok.Kind == "import" && i+1 < len(tokens) && tokens[i+1].Kind != "(" && tokens[i+1].Kind != "." {
				i = skipJSImportStmt(tokens, i)
				continue
			}
		case "c_family":
			if tok.Kind == "#include" && atLineStart {
				curLine := tok.Line
				for i < len(tokens) && tokens[i].Line == curLine {
					i++
				}
				continue
			}
			if atLineStart && (tok.Kind == "import" || tok.Kind == "using" || tok.Kind == "use") {
				curLine := tok.Line
				j := i + 1
				for j < len(tokens) {
					if tokens[j].Kind == ";" {
						j++
						break
					}
					if tokens[j].Kind == "{" && tok.Kind != "use" {
						// e.g. C++ using / Java class block isn't import; abort skip
						j = i
						break
					}
					if tokens[j].Line > curLine && tok.Kind == "import" {
						// Kotlin/Swift import without semicolon
						break
					}
					j++
				}
				if j > i {
					i = j
					continue
				}
			}
		}

		out = append(out, tok)
		i++
	}
	return out
}

func hasImportOnStatement(tokens []WinnowToken, start int) bool {
	baseLine := tokens[start].Line
	for j := start + 1; j < len(tokens) && j < start+16; j++ {
		if tokens[j].Line > baseLine {
			return false
		}
		if tokens[j].Kind == "import" {
			return true
		}
	}
	return false
}

func skipPythonImportStmt(tokens []WinnowToken, start int) int {
	depth := 0
	curLine := tokens[start].Line
	j := start
	for j < len(tokens) {
		k := tokens[j].Kind
		if depth == 0 && tokens[j].Line > curLine {
			break
		}
		if k == "(" {
			depth++
		} else if k == ")" && depth > 0 {
			depth--
			if depth == 0 {
				j++
				break
			}
		} else if depth == 0 && k == ";" {
			j++
			break
		}
		curLine = tokens[j].Line
		j++
	}
	return j
}

func skipJSImportStmt(tokens []WinnowToken, start int) int {
	depth := 0
	curLine := tokens[start].Line
	j := start
	for j < len(tokens) {
		k := tokens[j].Kind
		if depth == 0 && tokens[j].Line > curLine {
			break
		}
		if k == "{" || k == "(" {
			depth++
		} else if (k == "}" || k == ")") && depth > 0 {
			depth--
		} else if depth == 0 && k == ";" {
			j++
			break
		}
		curLine = tokens[j].Line
		j++
	}
	return j
}

func keywordsForLanguage(lang string) map[string]struct{} {
	switch lang {
	case "go":
		return goKeywords
	case "python":
		return pythonKeywords
	case "js":
		return jsKeywords
	case "c_family":
		return cFamilyKeywords
	default:
		return genericKeywords
	}
}

func makeKeywordSet(words ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}

var (
	goKeywords = makeKeywordSet(
		"break", "case", "chan", "const", "continue", "default", "defer", "else",
		"fallthrough", "for", "func", "go", "goto", "if", "import", "interface",
		"map", "package", "range", "return", "select", "struct", "switch", "type", "var",
		"bool", "byte", "complex64", "complex128", "error", "float32", "float64",
		"int", "int8", "int16", "int32", "int64", "rune", "string",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
		"true", "false", "iota", "nil", "append", "cap", "close", "complex", "copy",
		"delete", "imag", "len", "make", "new", "panic", "real", "recover",
	)
	pythonKeywords = makeKeywordSet(
		"False", "None", "True", "and", "as", "assert", "async", "await",
		"break", "class", "continue", "def", "del", "elif", "else", "except",
		"finally", "for", "from", "global", "if", "import", "in", "is",
		"lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
		"while", "with", "yield",
		"int", "float", "str", "bool", "list", "dict", "set", "tuple", "bytes",
		"len", "min", "max", "sum", "range", "enumerate", "zip", "abs", "round",
	)
	jsKeywords = makeKeywordSet(
		"async", "await", "break", "case", "catch", "class", "const", "continue",
		"default", "delete", "do", "else", "enum", "export", "extends", "false",
		"finally", "for", "from", "function", "if", "implements", "import", "in",
		"instanceof", "interface", "let", "new", "null", "of", "private", "protected",
		"public", "readonly", "return", "static", "super", "switch", "this", "throw",
		"true", "try", "type", "typeof", "undefined", "var", "void", "while", "with", "yield",
		"number", "string", "boolean", "bigint", "symbol", "object", "unknown", "never",
	)
	cFamilyKeywords = makeKeywordSet(
		"abstract", "as", "async", "await", "bool", "boolean", "break", "byte",
		"case", "catch", "char", "class", "const", "continue", "crate", "default",
		"do", "double", "else", "enum", "explicit", "export", "extends", "extern",
		"false", "final", "finally", "float", "fn", "for", "fun", "guard",
		"if", "impl", "implements", "import", "in", "inline", "int", "interface",
		"let", "long", "match", "mod", "mut", "namespace", "new", "nil", "null",
		"nullptr", "override", "package", "private", "protected", "pub", "public",
		"readonly", "return", "self", "Self", "short", "signed", "sizeof", "static",
		"struct", "super", "switch", "template", "this", "throw", "throws", "trait",
		"true", "try", "typedef", "typename", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
		"int8_t", "int16_t", "int32_t", "int64_t", "size_t", "usize", "isize",
		"u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64",
		"unsigned", "use", "using", "val", "var", "virtual", "void", "volatile", "where", "while",
	)
	genericKeywords = makeKeywordSet(
		"if", "else", "elif", "for", "while", "do", "switch", "case", "default",
		"break", "continue", "return", "func", "function", "def", "class", "struct",
		"type", "interface", "enum", "const", "var", "let", "true", "false", "null", "nil", "none",
	)
)
