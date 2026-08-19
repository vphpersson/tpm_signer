// Package pin obtains the TPM key's auth value from the person at the keyboard.
//
// It defers to systemd-ask-password rather than reading the terminal itself, which gets correct
// echo suppression, works when the caller's stdin is not the terminal, and reaches a graphical
// agent when there is no terminal at all.
package pin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

// DefaultTimeout bounds how long the prompt waits before giving up.
const DefaultTimeout = 90 * time.Second

// Prompt asks for a PIN once. The context cancels the prompt, which matters when the caller is
// interrupted while a person is staring at it.
func Prompt(ctx context.Context, message string, timeout time.Duration) ([]byte, error) {
	if message == "" {
		return nil, empty_error.New("message")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	// G204 flags the variable arguments. There is no shell here: exec.Command passes argv
	// directly, and the message is a prompt string rather than anything the callee interprets.
	command := exec.CommandContext( //nolint:gosec // G204: see above.
		ctx,
		"systemd-ask-password",
		"--icon=dialog-password",
		"--timeout="+strconv.Itoa(int(timeout.Seconds())),
		message,
	)

	var stdout bytes.Buffer
	command.Stdin = os.Stdin
	command.Stdout = &stdout
	command.Stderr = os.Stderr

	if err := command.Run(); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("systemd-ask-password: %w", err))
	}

	value := bytes.TrimRight(stdout.Bytes(), "\n")
	if len(value) == 0 {
		return nil, empty_error.New("pin")
	}

	return value, nil
}

// PromptConfirmed asks twice and requires the answers to match, for use when setting a new PIN.
func PromptConfirmed(ctx context.Context, message string, timeout time.Duration) ([]byte, error) {
	first, err := Prompt(ctx, message, timeout)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("prompt: %w", err))
	}

	second, err := Prompt(ctx, "Confirm "+message, timeout)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("prompt confirmation: %w", err))
	}
	defer func() {
		for index := range second {
			second[index] = 0
		}
	}()

	if !bytes.Equal(first, second) {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the two entries differ", altshiftErrors.ErrValidationError),
		)
	}

	return first, nil
}
