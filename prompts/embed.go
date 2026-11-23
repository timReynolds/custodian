package prompts

import "embed"

// PromptFS embeds static server-side Stage B decision model prompt templates.
//
//go:embed stageb_security_review_v1.txt stageb_ip_provenance_v1.txt
var PromptFS embed.FS
