package client

import "testing"

func TestNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "record miss envelope",
			body: `{"error":"content chain not found"}`,
			want: "not found: /proof/v1/content/example — relay says: content chain not found",
		},
		{
			name: "bare route miss",
			body: "404 page not found\n",
			want: "not found: /proof/v1/content/example — no error envelope in the response; this relay may not serve this route at all (older version or capability off)",
		},
		{
			name: "empty JSON error",
			body: `{"error":""}`,
			want: "not found: /proof/v1/content/example — no error envelope in the response; this relay may not serve this route at all (older version or capability off)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := notFoundError("/proof/v1/content/example", []byte(tt.body)).Error(); got != tt.want {
				t.Fatalf("notFoundError() = %q, want %q", got, tt.want)
			}
		})
	}
}
