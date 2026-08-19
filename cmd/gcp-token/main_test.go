package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//nolint:paralleltest // Redirects os.Stdout, which is process-wide state.
func TestEmit(t *testing.T) {
	testCases := []struct {
		name       string
		token      string
		exportForm bool
		want       string
	}{
		{name: "bare token", token: "ya29.test", want: "ya29.test\n"},
		{
			name:       "export statement",
			token:      "ya29.test",
			exportForm: true,
			want:       "export GOOGLE_OAUTH_ACCESS_TOKEN=ya29.test\n",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // Redirects os.Stdout, as above.
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatalf("pipe: %v", err)
			}

			original := os.Stdout
			os.Stdout = writer
			emit(testCase.token, testCase.exportForm)
			os.Stdout = original

			if err := writer.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}

			output, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			if string(output) != testCase.want {
				t.Errorf("emitted %q, want %q", output, testCase.want)
			}
			// A stray newline inside the value would corrupt the shell assignment.
			if strings.Count(string(output), "\n") != 1 {
				t.Errorf("expected exactly one newline, got %q", output)
			}
		})
	}
}

func TestDefaultKeyPath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		want string
	}{
		{name: "ends at the key file", want: "gcp.tpm"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			path := defaultKeyPath()
			if filepath.Base(path) != testCase.want {
				t.Errorf("path %q does not end in %q", path, testCase.want)
			}
		})
	}
}
