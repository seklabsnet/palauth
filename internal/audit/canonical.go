package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalJSON serializes v to JSON with keys sorted alphabetically at all levels.
// This is critical for hash chain integrity: the same data must always produce
// the same bytes regardless of map iteration order.
func CanonicalJSON(v any) ([]byte, error) {
	normalized, err := normalize(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		return nil, fmt.Errorf("canonical json encode: %w", err)
	}
	// json.Encoder.Encode appends a newline; trim it for consistent hashing.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// normalize recursively converts the value to a form where all maps have
// sorted keys, producing deterministic JSON output.
func normalize(v any) (any, error) {
	switch val := v.(type) {
	case map[string]any:
		return normalizeMap(val)
	case []any:
		return normalizeSlice(val)
	default:
		// For structs and other types, round-trip through JSON to get map[string]any.
		data, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("canonical json marshal: %w", err)
		}
		var decoded any
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("canonical json unmarshal: %w", err)
		}
		// If it decoded to a map, normalize it.
		if m, ok := decoded.(map[string]any); ok {
			return normalizeMap(m)
		}
		if s, ok := decoded.([]any); ok {
			return normalizeSlice(s)
		}
		return decoded, nil
	}
}

// normalizeMap sorts keys and recursively normalizes values.
func normalizeMap(m map[string]any) (*sortedMap, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	entries := make([]sortedMapEntry, 0, len(keys))
	for _, k := range keys {
		nv, err := normalize(m[k])
		if err != nil {
			return nil, err
		}
		entries = append(entries, sortedMapEntry{Key: k, Value: nv})
	}

	return &sortedMap{Entries: entries}, nil
}

// normalizeSlice recursively normalizes each element.
func normalizeSlice(s []any) ([]any, error) {
	result := make([]any, len(s))
	for i, item := range s {
		nv, err := normalize(item)
		if err != nil {
			return nil, err
		}
		result[i] = nv
	}
	return result, nil
}

// sortedMap is a map that marshals to JSON with keys in sorted order.
type sortedMap struct {
	Entries []sortedMapEntry
}

type sortedMapEntry struct {
	Key   string
	Value any
}

func (sm *sortedMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, entry := range sm.Entries {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyBytes, err := json.Marshal(entry.Key)
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')

		valBytes, err := json.Marshal(entry.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
