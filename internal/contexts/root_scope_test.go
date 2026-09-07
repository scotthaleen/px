package contexts

import "testing"

func TestClassifyOfferedRootForOS(t *testing.T) {
	tests := []struct {
		name, path, goos, want string
		wantErr                bool
	}{
		{name: "unix root", path: "/", goos: "linux", want: OfferedRootScopeFilesystemRoot},
		{name: "unix directory", path: "/srv", goos: "linux", want: OfferedRootScopeNarrow},
		{name: "windows drive backslash", path: `C:\`, goos: "windows", want: OfferedRootScopeFilesystemRoot},
		{name: "windows drive slash", path: `z:/`, goos: "windows", want: OfferedRootScopeFilesystemRoot},
		{name: "windows drive child", path: `C:\data`, goos: "windows", want: OfferedRootScopeNarrow},
		{name: "windows drive relative", path: `C:`, goos: "windows", wantErr: true},
		{name: "windows drive relative child", path: `C:data`, goos: "windows", wantErr: true},
		{name: "windows current drive rooted", path: `\data`, goos: "windows", wantErr: true},
		{name: "windows UNC", path: `\\server\share\`, goos: "windows", wantErr: true},
		{name: "windows extended drive", path: `\\?\C:\`, goos: "windows", wantErr: true},
		{name: "windows volume GUID", path: `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\`, goos: "windows", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := offeredRootScopeForOS(test.path, test.goos)
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("offeredRootScopeForOS(%q, %q) = %q, %v; want %q, error %v", test.path, test.goos, got, err, test.want, test.wantErr)
			}
		})
	}
}
