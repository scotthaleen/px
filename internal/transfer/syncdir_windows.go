package transfer

import "os"

func syncRootDirectory(*os.Root, string) error {
	// Windows does not expose directory handles through os.Root that can be
	// passed to FlushFileBuffers. NTFS journals the exclusive link operation.
	return nil
}
