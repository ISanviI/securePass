# Makefile
CC = gcc
CFLAGS = -Wall -O2
TARGET = securePass
SRC = src/main.c src/auth.c src/storage.c
LIBS = -lpam -lpam_misc
PAM_CONFIG = pam/securePass

# The DESTDIR variable is used to specify a temporary directory for installation.
# During packaging --- DESTDIR="$pkgdir" (set by makepkg)
# During testing	--- Set DESTDIR=/tmp/test manually while compiling using `make DESTDIR=/tmp/test`
# After install	--- There is no DESTDIR -> the files are now in real /usr/bin, /etc, etc.

# "makepkg" is the official Arch tool that:
# Reads PKGBUILD
# Creates a clean build environment
# Compiles project
# Installs the files into a temporary $pkgdir (your DESTDIR)
# Packages everything into a .pkg.tar.zst file (Arch installable format) (AUR - Arch User Repository)

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# -mxxx - 3-digit number = owner, group, and others permissions.
# Example: 765 = owner can read/write/execute, group can read/write, others can read/execute. 4 = read
# /etc directory is for system configuration files, so it should not be writable by non-root users.
# pam folder is purely for authentication.
# Package installation only installs the package's compiled binary file and not the whole project unless specified.
install:
	install -Dm755 $(TARGET) "$(DESTDIR)/usr/bin/$(TARGET)" 
	install -Dm644 $(PAM_CONFIG) "$(DESTDIR)/etc/pam.d/$(TARGET)"
uninstall:
	rm -f "$(DESTDIR)/usr/bin/$(TARGET)"
	rm -f /etc/pam.d/$(TARGET)

clean:
	rm -f $(TARGET)

package: all install
	@echo "Package created successfully."