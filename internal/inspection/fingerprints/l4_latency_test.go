package fingerprints

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestL4_800KB_LinearLatency(t *testing.T) {
	cases := []struct {
		name string
		unit string
		tail string
	}{
		{"block_cmt_800kb.js", `"ab"/*`, ""},
		{"line_cmt_800kb.js", `"ab"//`, ""},
		{"hash_cmt_800kb.py", `"ab"#`, ""},
		{"js_interp_800kb.js", "`ab`${", ""},
		{"py_fstr_800kb.py", `f"ab"{`, ""},
		{"a85_decoy_800kb.js", `<~ `, `~>`},
		{"obj_arr_800kb.js", `{s:"ab"},`, ""},
		{"idx_arr_800kb.js", `a[0]="ab";`, ""},
		{"eq_b64_800kb.txt", `a=b=`, ""},
		{"eq_lines_800kb.txt", "key=abcd\n", ""},
	}
	for _, tc := range cases {
		payload := bytes.Repeat([]byte(tc.unit), (800*1024)/len(tc.unit))
		if tc.tail != "" {
			payload = append(payload, tc.tail...)
		}
		start := time.Now()
		res := inspectFileL4(context.Background(), tc.name, payload)
		el := time.Since(start)
		if len(res.Findings) != 0 || res.ExtraSkipped != 0 {
			t.Fatalf("%s expected 0 findings and 0 skipped, got findings=%d skipped=%d", tc.name, len(res.Findings), res.ExtraSkipped)
		}
		if isRaceEnabled || testing.Short() {
			t.Logf("L4 %s (%d bytes): %v (non-gating under -race / -short per R5)", tc.name, len(payload), el)
			if el > 15*time.Second {
				t.Fatalf("%s took %v (exceeded 15s quadratic-DoS safety ceiling under -race / -short)", tc.name, el)
			}
		} else {
			if el > 1500*time.Millisecond {
				t.Fatalf("%s took %v (expected O(N) well under 1.5s)", tc.name, el)
			}
			t.Logf("L4 %s (%d bytes): %v", tc.name, len(payload), el)
		}
	}
}
