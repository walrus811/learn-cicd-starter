package auth

import (
	"errors"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		expected string
		err      error
	}{
		{
			name: "Valid Authorization header",
			headers: map[string][]string{
				"Authorization": {"ApiKey 123"},
			},
			expected: "123",
			err:      nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(test.headers)
			if apiKey != test.expected {
				t.Errorf("expected %s, got %s", test.expected, apiKey)
			}
			if err != test.err {
				t.Errorf("expected %v, got %v", test.err, err)
			}
		})
	}
}

func TestGetApiKeyWithErr(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		expected string
		err      error
	}{
		{
			name: "No Authorization header",
			headers: map[string][]string{
				"Authorization": {},
			},
			expected: "",
			err:      ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization header",
			headers: map[string][]string{
				"Authorization": {"ApiKey"},
			},
			expected: "",
			err:      errors.New("malformed authorization header(ApiKey)"),
		},
		{
			name: "Malformed Authorization header",
			headers: map[string][]string{
				"Authorization": {"babo"},
			},
			expected: "",
			err:      errors.New("malformed authorization header(babo)"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(test.headers)
			if apiKey != test.expected {
				t.Errorf("expected %s, got %s", test.expected, apiKey)
			}
			if err == nil {
				t.Errorf("expected %v, got %v", test.err, err)
			}
		})
	}
}
