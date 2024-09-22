package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectError bool
		errorType   error
	}{
		{
			name:        "Valid API Key",
			headers:     http.Header{"Authorization": []string{"ApiKey abc123"}},
			expectedKey: "abc123",
			expectError: false,
		},
		{
			name:        "No Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectError: true,
			errorType:   ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Empty Authorization Header",
			headers:     http.Header{"Authorization": []string{""}},
			expectedKey: "",
			expectError: true,
			errorType:   ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization Header: Missing ApiKey",
			headers:     http.Header{"Authorization": []string{"Bearer abc123"}},
			expectedKey: "",
			expectError: true,
			errorType:   errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed Authorization Header: Missing Token",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectError: true,
			errorType:   errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed Authorization Header: Extra Fields",
			headers:     http.Header{"Authorization": []string{"ApiKey abc123 extra"}},
			expectedKey: "abc123",
			expectError: false, // Update to false if extra fields are allowed
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(test.headers)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if err.Error() != test.errorType.Error() {
					t.Errorf("Expected error: %v, got: %v", test.errorType, err)
				}
			} else {
				if apiKey != test.expectedKey {
					t.Errorf("Expected API key: %v, got: %v", test.expectedKey, apiKey)
				}
			}
		})
	}
}
