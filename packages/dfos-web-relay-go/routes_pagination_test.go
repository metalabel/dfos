package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogResponsesEmitNextWithoutCursorAlias(t *testing.T) {
	store := NewMemoryStore()
	identity := createTestIdentity(t)
	contentToken, contentID, _ := createTestContent(t, identity)
	results := IngestOperations([]string{identity.token, contentToken}, store)
	for _, result := range results {
		if result.Status != "new" && result.Status != "duplicate" {
			t.Fatalf("ingest %s: status=%s error=%s", result.CID, result.Status, result.Error)
		}
	}

	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	paths := []string{
		proofBasePath + "/log",
		proofBasePath + "/identities/" + identity.did + "/log",
		proofBasePath + "/content/" + contentID + "/log",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			relay.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
			}

			var body map[string]json.RawMessage
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if _, ok := body["next"]; !ok {
				t.Fatal("response missing next field")
			}
			if cursor, ok := body["cursor"]; ok {
				t.Fatalf("response contains removed cursor alias: %s", cursor)
			}
		})
	}
}
