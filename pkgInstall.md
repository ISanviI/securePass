# `pacman` vs `yay` — How They Work (for Arch)
### pacman
Official package manager for Arch Linux.
Installs precompiled, signed packages from Arch’s official repositories.
Commands like pacman -S pkgname only pull from repos listed in /etc/pacman.conf (maintained by Arch developers & Trusted Users).
Can also install any local package file (.pkg.tar.zst) via pacman -U file, even if it’s not in the official repos.

### yay
An AUR helper that wraps around pacman.
Can install from both official repos and the AUR (Arch User Repository).
For AUR packages, it:
* Downloads the PKGBUILD from the AUR (a Git repo of build scripts).
* Builds the package locally using makepkg.
* Installs it via pacman -U.

### AUR (Arch User Repository)
Community-maintained collection of `PKGBUILD` scripts, not binaries.
Anyone can upload packages after creating an AUR account — no pre-approval, but community moderation exists.
Official repo inclusion requires review by Arch maintainers/TUs.

### Key Points
pacman doesn’t care where a `.pkg.tar.zst` comes from — as long as it’s in the correct format, it can install it.
yay relies on pacman to do the final install step.
AUR packages are built locally; official repo packages are downloaded as binaries.
Security: Only trust AUR PKGBUILDs from reputable sources before building/installing.