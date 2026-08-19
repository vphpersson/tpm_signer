package pin

import (
	"context"
	"testing"
	"time"
)

func TestPromptValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
		timeout time.Duration
	}{
		{name: "empty message", message: "", timeout: time.Second},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Prompt(context.Background(), testCase.message, testCase.timeout); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}

func TestPromptConfirmedValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
	}{
		{name: "empty message"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := PromptConfirmed(context.Background(), testCase.message, time.Second); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}
