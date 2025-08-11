package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-api-key"},
			},
			expectedKey: "my-api-key",
			expectedErr: nil,
		},
		{
			name:        "Missing Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Empty Authorization Header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - No ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-api-key"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Only ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - No Space",
			headers: http.Header{
				"Authorization": []string{"ApiKeymy-api-key"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}
			if !errors.Is(err, tt.expectedErr) && !reflect.DeepEqual(err, tt.expectedErr) {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}
