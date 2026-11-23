package openapi

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	liberrors "github.com/pb33f/libopenapi-validator/errors"
	"github.com/pb33f/libopenapi/bundler"
	"github.com/pb33f/libopenapi/datamodel"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"

	"github.com/timreynolds/custodian/api"
)

// LoadDocument parses the embedded OpenAPI 3.1 contract offline using api.SpecFS.
func LoadDocument() (libopenapi.Document, *libopenapi.DocumentModel[v3.Document], error) {
	return LoadFromFS(api.SpecFS, "openapi.yaml")
}

// LoadFromFS loads and builds an OpenAPI 3.1 Document and V3 model strictly offline from fsys.
func LoadFromFS(fsys fs.FS, rootFile string) (libopenapi.Document, *libopenapi.DocumentModel[v3.Document], error) {
	if fsys == nil {
		return nil, nil, errors.New("spec filesystem must not be nil")
	}
	specBytes, err := fs.ReadFile(fsys, rootFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read embedded spec %q: %w", rootFile, err)
	}

	cfg := datamodel.NewDocumentConfiguration()
	cfg.AllowFileReferences = true
	cfg.AllowRemoteReferences = false
	cfg.BasePath = "/custodian-spec"
	cfg.SpecFilePath = rootFile
	cfg.LocalFS = fsys
	cfg.ResolveNestedRefsWithDocumentContext = true

	doc, err := libopenapi.NewDocumentWithConfiguration(specBytes, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("parse OpenAPI document: %w", err)
	}

	v3Model, err := doc.BuildV3Model()
	if err != nil {
		return nil, nil, fmt.Errorf("build OpenAPI v3 model: %w", err)
	}
	if v3Model == nil {
		return nil, nil, errors.New("built OpenAPI v3 model is nil")
	}
	return doc, v3Model, nil
}

// ValidateSpec validates both the root OpenAPI 3.1 document and its bundled output
// so all external ./schemas/*.yaml references are strictly schema-validated offline.
func ValidateSpec(doc libopenapi.Document) error {
	if doc == nil {
		return errors.New("OpenAPI document must not be nil")
	}

	rootVal, errs := validator.NewValidator(doc)
	if len(errs) > 0 {
		return fmt.Errorf("create root validator: %w", errors.Join(errs...))
	}
	defer rootVal.Release()

	ok, valErrs := rootVal.ValidateDocument()
	if !ok || len(valErrs) > 0 {
		return formatValidationErrors("root OpenAPI document", valErrs)
	}

	v3Model, err := doc.BuildV3Model()
	if err != nil {
		return fmt.Errorf("build v3 model for bundling: %w", err)
	}

	bundledBytes, err := bundler.BundleDocument(&v3Model.Model)
	if err != nil {
		return fmt.Errorf("bundle OpenAPI document: %w", err)
	}

	bundledCfg := datamodel.NewDocumentConfiguration()
	bundledCfg.AllowFileReferences = false
	bundledCfg.AllowRemoteReferences = false

	bundledDoc, err := libopenapi.NewDocumentWithConfiguration(bundledBytes, bundledCfg)
	if err != nil {
		return fmt.Errorf("parse bundled OpenAPI document: %w", err)
	}

	bundledVal, errs := validator.NewValidator(bundledDoc)
	if len(errs) > 0 {
		return fmt.Errorf("create bundled validator: %w", errors.Join(errs...))
	}
	defer bundledVal.Release()

	ok, valErrs = bundledVal.ValidateDocument()
	if !ok || len(valErrs) > 0 {
		return formatValidationErrors("bundled OpenAPI document", valErrs)
	}
	return nil
}

// NewHTTPValidator returns a reusable libopenapi-validator Validator built from the embedded spec.
func NewHTTPValidator() (validator.Validator, error) {
	doc, _, err := LoadDocument()
	if err != nil {
		return nil, err
	}
	v, errs := validator.NewValidator(doc)
	if len(errs) > 0 {
		return nil, fmt.Errorf("create HTTP validator: %w", errors.Join(errs...))
	}
	return v, nil
}

func formatValidationErrors(scope string, valErrs []*liberrors.ValidationError) error {
	if len(valErrs) == 0 {
		return fmt.Errorf("%s failed validation with unknown error", scope)
	}
	msgs := make([]string, 0, len(valErrs))
	for _, ve := range valErrs {
		if ve == nil {
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s: %s (line %d, col %d)", ve.Message, ve.Reason, ve.SpecLine, ve.SpecCol))
	}
	return fmt.Errorf("%s validation failed:\n- %s", scope, strings.Join(msgs, "\n- "))
}
