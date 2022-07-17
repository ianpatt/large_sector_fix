# large_sector_fix
possible fix for sound issues in skyrim on non-512-byte sector drives

an SKSE64 plugin compatible with all versions of Skyrim SE/AE.

this plugin is useful if you have installed Skyrim on a drive that does not use 512 byte sectors. in order to optimize disk access and memory, and possibly for better performance on consoles, the sound .bsa is opened with the flag [`FILE_FLAG_NO_BUFFERING`](https://docs.microsoft.com/en-us/windows/win32/fileio/file-buffering). this is an "I know what I am doing" flag that tells the operating system to operate at the raw disk sector level, bypassing the disk cache system. files that are opened this way take an accelerated path from the disk to memory, avoiding additional copies. this is faster, but comes with some restrictions. the primary restriction is that all file operations must both start at an offset and have a size that is an even multiple of the disk sector. this is all well and good when essentially all hard drives have sector sizes of 512 bytes and the game isn't installed to anything else. this assumption worked fine for roughly one year, breaking when Windows 8 added support for [4096 byte sectors](https://en.wikipedia.org/wiki/Advanced_Format). with Skyrim installed on one of these drives, most read operations from the sound .bsa fail, only succeeding when the offset and size happen to line up with the larger sector size.

## Installation

Copy to Data/SKSE/Plugins/. Create these folders if they don't exist. Currently there is no log file or feedback; it either works or it doesn't.
