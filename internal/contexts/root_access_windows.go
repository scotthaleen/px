package contexts

// Windows has no POSIX search bit. Root validation relies on opening and
// listing the directory under the current user token and on os.Root enforcing
// the filesystem ACL during later traversal.
func validateRootSearch(string) error {
	return nil
}
