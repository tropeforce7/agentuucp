// Package regular opens files by the handle, not the name.
//
// A name list is one guard against a device, and a name list is never
// complete: Windows has CON, NUL, COM1 and their relatives, a home may be
// on a filesystem that maps names nobody here has thought of, and a
// named pipe, a socket or a symbolic link can be planted under any name
// at all by whoever can write the directory. The other guard is the
// handle. After the open, the file knows what it is, and this package
// asks it: OpenFile opens, calls Stat on the handle, and refuses anything
// whose mode is not a regular file before a byte moves in either
// direction; Dir does the same with the mode inverted, for a directory
// that is opened to be synced. On Unix every open of a file carries
// O_NOFOLLOW, so a symbolic link under the name is refused as a link
// rather than followed to wherever it points. The flag covers the last
// component only: a link among the directories above the name is
// followed, so what keeps those directories the program's is where the
// path came from, which the ledger says for every row, and not this
// package. Dir follows a link, since
// a link that resolves to a directory is a directory (an operator's home
// or authority behind a link is the ordinary case) and the handle check
// judges what it resolves to. On Windows every open of a file carries
// FILE_FLAG_OPEN_REPARSE_POINT instead, so a reparse point under the name
// is opened as itself and the handle asked (S57). Go 1.27 reports a
// symbolic link as ModeSymlink, refused as a link as on unix, and every
// other tag as ModeIrregular but one, a deduplicated file, which it
// reports as regular. A reparse point on a directory, a mount point (a
// junction) among them, is refused saying so, from the handle's
// attributes, by an open for reading; one for writing is refused by the
// platform, which opens no directory to write. Any other reparse point,
// a deduplicated file or a cloud placeholder, is never read or written
// through that handle, which is on the reparse data, but opened again
// without the flag, neither creating nor truncating, for the platform to
// open the file it stands for; that handle must be on the very file the
// first one was (os.SameFile), and is then judged as an open's always
// was, so a deduplicated file is used and a placeholder Go reports as
// irregular is refused, as before, and a truncate asked for is made on
// the judged handle. Go truncates as it opens, on the flagged handle, so
// an open asked to truncate has by then emptied the object at the name,
// the reparse point's own, and never what a link names. As on unix the flag covers the last component
// only, and a link or junction among the directories above is followed.
// An exclusive create refuses a link as an existing entry without
// following it. A hard link is the file it names on every platform, and
// no open refuses it. A create is exclusive
// (O_CREATE|O_EXCL), so the program never opens something that already
// stood under the name: an existing file, a device, a link. There is no
// rename here and no temporary file, since a rename's destination has no
// handle to ask.
//
// Every file the program reads or creates by a name that came from the
// network, or from a directory entry it read back, goes through this
// package; the file-open ledger in internal/fileopens says which rows
// those are, and its test fails one that opens by the plain os call. An
// operator's own input file named whole on the command line or in a
// configuration file is not held to this: a passphrase file from process
// substitution is a pipe on purpose.
//
// The package adds exactly one error of its own, *ModeError, for a handle
// whose mode is not what was asked for, and passes every other error
// through exactly as os returned it, unwrapped: errors.Is(err,
// os.ErrNotExist) and errors.Is(err, os.ErrExist) hold for every caller,
// since about forty sites treat a missing file as a state (no cursor yet,
// no anchor, nothing pending) and extraction's "already exists" sentence
// is made from ErrExist. A symbolic link refused by O_NOFOLLOW is the
// one os error this package reads before passing on: the platform
// reports it as ELOOP (Linux, macOS) or EMLINK (FreeBSD), and when Lstat
// confirms a link under the name the error is a *ModeError saying so;
// otherwise the os error is returned as it came.
//
// On Windows the DOS device names answer to their names in every
// directory on some versions and not on others, and what CreateFile does
// when asked to create one exclusively is not something this package
// assumes: CREATE_NEW on a device name may fail with the platform's own
// error or may hand back the device's handle. Either is a refusal here —
// the os error passed through, or the handle check finding a character
// device — and in neither case is a byte written or an entry removed,
// since an exclusive create that succeeded and produced a device made
// nothing to remove. On windows-2025-vs2026 (Windows Server 2025,
// go1.27.0) NUL under a directory was the device, handed back by Open
// and by the exclusive create alike and refused by the handle both
// times, while CON, nul.txt and com1.txt were ordinary names there,
// made as regular files; older Windows treats more of the names as
// devices, which is what the handle check is for. A directory under the
// name of an exclusive create is refused by the platform in one of two
// words: EEXIST on Linux and macOS, EISDIR on Windows, where CreateFile
// refuses a directory opened for writing as access denied and Go's
// syscall.Open reports that as EISDIR.
//
// O_NONBLOCK is on every Unix open here for one reason: open(2) of a
// FIFO for reading blocks until a writer arrives, so without it a pipe
// planted under a name would hold the program before the handle could
// be asked. With it a FIFO opens at once and is refused by its mode, a
// FIFO opened for writing is refused by the platform (ENXIO, passed
// through), and a regular file, on which the flag changes nothing, is
// put back into blocking mode once its handle has been checked.
// TestLimitADeviceIsRefusedByItsHandle asserts on Windows, for CON, NUL,
// nul.txt and com1.txt through Open and Create, that each is refused by
// the handle or by the platform or is an ordinary name made as a regular
// file, never a device handed back as a regular file, and logs which;
// the Windows CI job runs it, and its log is the record of what Go
// actually does there.
package regular
