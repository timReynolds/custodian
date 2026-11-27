package quarantine

import (
	"sort"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

// PushManifestSchemaVersion is the current canonical PushManifest schema version.
const PushManifestSchemaVersion = "1"

// PushManifestRefUpdate is the canonical ref transition recorded in PushManifest.
type PushManifestRefUpdate struct {
	RefName string `json:"ref_name"`
	OldOID  string `json:"old_oid"`
	NewOID  string `json:"new_oid"`
}

// PushManifestLFSObject is the canonical LFS pointer tuple recorded in PushManifest.
type PushManifestLFSObject struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// PushManifest captures the content-pure canonical inventory of a quarantined push.
// It excludes wall-clock timestamps, session IDs, and packfile compression/order details.
type PushManifest struct {
	SchemaVersion string                  `json:"schema_version"`
	RefUpdates    []PushManifestRefUpdate `json:"ref_updates"`
	Commits       []string                `json:"commits"`
	Trees         []string                `json:"trees"`
	Blobs         []string                `json:"blobs"`
	Tags          []string                `json:"tags"`
	LFSObjects    []PushManifestLFSObject `json:"lfs_objects"`
}

// ComputePushManifestDigest normalizes, canonicalizes, and SHA-256 hashes a PushManifest.
func ComputePushManifestDigest(m PushManifest) (PushManifest, []byte, string, error) {
	if strings.TrimSpace(m.SchemaVersion) == "" {
		m.SchemaVersion = PushManifestSchemaVersion
	}

	refs := make([]PushManifestRefUpdate, 0, len(m.RefUpdates))
	for _, r := range m.RefUpdates {
		oldOID, err := domain.ParseGitSHA(r.OldOID)
		if err != nil {
			return PushManifest{}, nil, "", err
		}
		newOID, err := domain.ParseGitSHA(r.NewOID)
		if err != nil {
			return PushManifest{}, nil, "", err
		}
		refs = append(refs, PushManifestRefUpdate{
			RefName: r.RefName,
			OldOID:  oldOID,
			NewOID:  newOID,
		})
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].RefName != refs[j].RefName {
			return refs[i].RefName < refs[j].RefName
		}
		if refs[i].OldOID != refs[j].OldOID {
			return refs[i].OldOID < refs[j].OldOID
		}
		return refs[i].NewOID < refs[j].NewOID
	})
	m.RefUpdates = refs

	var err error
	if m.Commits, err = normalizeSortedUniqueOIDs(m.Commits); err != nil {
		return PushManifest{}, nil, "", err
	}
	if m.Trees, err = normalizeSortedUniqueOIDs(m.Trees); err != nil {
		return PushManifest{}, nil, "", err
	}
	if m.Blobs, err = normalizeSortedUniqueOIDs(m.Blobs); err != nil {
		return PushManifest{}, nil, "", err
	}
	if m.Tags, err = normalizeSortedUniqueOIDs(m.Tags); err != nil {
		return PushManifest{}, nil, "", err
	}

	lfsOut := make([]PushManifestLFSObject, 0, len(m.LFSObjects))
	seenLFS := make(map[PushManifestLFSObject]struct{}, len(m.LFSObjects))
	for _, obj := range m.LFSObjects {
		normObj := PushManifestLFSObject{
			OID:  strings.ToLower(strings.TrimSpace(obj.OID)),
			Size: obj.Size,
		}
		if normObj.OID == "" {
			return PushManifest{}, nil, "", domain.BadRequest("INVALID_LFS_OID", "LFS object OID must not be empty")
		}
		if normObj.Size < 0 {
			return PushManifest{}, nil, "", domain.BadRequest("INVALID_LFS_SIZE", "LFS object size must not be negative")
		}
		if _, ok := seenLFS[normObj]; ok {
			continue
		}
		seenLFS[normObj] = struct{}{}
		lfsOut = append(lfsOut, normObj)
	}
	sort.Slice(lfsOut, func(i, j int) bool {
		if lfsOut[i].OID != lfsOut[j].OID {
			return lfsOut[i].OID < lfsOut[j].OID
		}
		return lfsOut[i].Size < lfsOut[j].Size
	})
	m.LFSObjects = lfsOut

	canonicalJSON, err := domain.CanonicalJSONBytes(m)
	if err != nil {
		return PushManifest{}, nil, "", err
	}
	digest := domain.SHA256Hex(canonicalJSON)
	return m, canonicalJSON, digest, nil
}

func buildPushManifest(refs []RefUpdate, hist historyExtractResult, lfs []domain.PushLFSObject) (PushManifest, []byte, string, error) {
	refList := make([]PushManifestRefUpdate, 0, len(refs))
	for _, r := range refs {
		refList = append(refList, PushManifestRefUpdate{
			RefName: r.RefName,
			OldOID:  r.OldOID,
			NewOID:  r.NewOID,
		})
	}

	commits := make([]string, 0, len(hist.commits))
	for _, c := range hist.commits {
		commits = append(commits, c.OID)
	}
	blobs := make([]string, 0, len(hist.blobs))
	for _, b := range hist.blobs {
		blobs = append(blobs, b.OID)
	}
	tags := make([]string, 0, len(hist.tags))
	for _, t := range hist.tags {
		tags = append(tags, t.OID)
	}

	lfsList := make([]PushManifestLFSObject, 0, len(lfs))
	for _, obj := range lfs {
		lfsList = append(lfsList, PushManifestLFSObject{
			OID:  obj.OID,
			Size: obj.Size,
		})
	}

	return ComputePushManifestDigest(PushManifest{
		SchemaVersion: PushManifestSchemaVersion,
		RefUpdates:    refList,
		Commits:       commits,
		Trees:         append([]string(nil), hist.trees...),
		Blobs:         blobs,
		Tags:          tags,
		LFSObjects:    lfsList,
	})
}

func normalizeLFSObjects(in []domain.PushLFSObject) []domain.PushLFSObject {
	if len(in) == 0 {
		return []domain.PushLFSObject{}
	}
	seen := make(map[domain.PushLFSObject]struct{}, len(in))
	out := make([]domain.PushLFSObject, 0, len(in))
	for _, obj := range in {
		normObj := domain.PushLFSObject{
			OID:  strings.ToLower(strings.TrimSpace(obj.OID)),
			Size: obj.Size,
		}
		if _, ok := seen[normObj]; ok {
			continue
		}
		seen[normObj] = struct{}{}
		out = append(out, normObj)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OID != out[j].OID {
			return out[i].OID < out[j].OID
		}
		return out[i].Size < out[j].Size
	})
	return out
}

func normalizeSortedUniqueOIDs(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		oid, err := domain.ParseGitSHA(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[oid]; ok {
			continue
		}
		seen[oid] = struct{}{}
		out = append(out, oid)
	}
	sort.Strings(out)
	return out, nil
}
