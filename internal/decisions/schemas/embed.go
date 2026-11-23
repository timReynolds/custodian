package schemas

import "embed"

// SchemaFS embeds Stage B JSON Schema definitions.
//
//go:embed assessment_result.schema.json
var SchemaFS embed.FS

// AssessmentResultSchemaBytes returns the embedded Stage B AssessmentResult JSON Schema bytes.
func AssessmentResultSchemaBytes() ([]byte, error) {
	return SchemaFS.ReadFile("assessment_result.schema.json")
}
