# fver
CLI tool for signing and verifying files using `secp384r1` keys.
## Commands
* `login` - Checks login status, creates new key and username if not logged in
* `sign <file>` - Signs file and pushes signature to the server.
* `verify <file>` - Pulls all signatures of specified file and verifies them
## Notes
There is no official server running yet. You can start your own by `cargo run` in `server` directory