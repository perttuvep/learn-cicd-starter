package auth_test

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
	"reflect"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		want    string
		wantErr bool
	}{
		"valid API key": {
			headers: http.Header{"Authorization": []string{"ApiKey valid_api_key"}},
			want:    "valid_api_key",
			wantErr: false,
		},
		"no authorization header": {
			headers: http.Header{},
			want:    "",
			wantErr: true,
		},
		"malformed authorization header - no space": {
			headers: http.Header{"Authorization": []string{"ApiKeyvalid_api_key"}},
			want:    "",
			wantErr: true,
		},
		"malformed authorization header - wrong prefix": {
			headers: http.Header{"Authorization": []string{"Bearer valid_api_key"}},
			want:    "",
			wantErr: true,
		},
		"malformed authorization header - too few parts": {
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: true,
		},
		"multiple authorization headers": {
			headers: http.Header{
				"Authorization": []string{"ApiKey valid_api_key", "ApiKey another_key"},
			},
			want:    "valid_api_key",
			wantErr: false,
		},
		"extra spaces": {
			headers: http.Header{"Authorization": []string{"ApiKey  valid_api_key  "}},
			want:    "",
			wantErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, gotErr := auth.GetAPIKey(tc.headers)
			if gotErr != nil {
				if !tc.wantErr {
					t.Errorf("GetAPIKey() failed: %v", gotErr)
				}
				if tc.wantErr && gotErr == auth.ErrNoAuthHeaderIncluded && tc.headers.Get("Authorization") != "" {
					t.Errorf("GetAPIKey() returned wrong error. Got %v, expected ErrNoAuthHeaderIncluded, when Authorization header exists", gotErr)
				}
				if tc.wantErr && gotErr != auth.ErrNoAuthHeaderIncluded && tc.headers.Get("Authorization") == "" {
					t.Errorf("GetAPIKey() returned wrong error. Got %v, expected ErrNoAuthHeaderIncluded, when Authorization header is empty", gotErr)
				}
				return
			}
			if tc.wantErr {
				t.Fatal("GetAPIKey() succeeded unexpectedly")
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("GetAPIKey() = %v, want %v", got, tc.want)
			}
		})
	}
}
