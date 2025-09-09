# Makefile
# TODO - chown root:securepass securepass.db 	chmod 600 securepass.db
# // Get rid of storage.c as to remove securePass.db
# // Segregate the authentication and storage logic into separate files from auth.c.
# // Encrypt with AES-256-GCM using a random IV
# // Store IV + ciphertext in the DB
# // Key comes from secure source (OS keyring, KDF)
# // Using mlock() or libsodium sodium_mlock() on sensitive buffers to avoid data swap across memory.
# // Use a proper JSON parser (e.g., jsmn or cJSON) rather than the ad-hoc parser used here.

# Current make command - 
# 	Testing ---> make DESTDIR=/tmp/pkg CFLAGS="$(CFLAGS) -DDB_FILE=\\\"$(DESTDIR)$(DBFILE)\\\""
# 	Installation ---> make
# 	Execution ---> ./securePass
# \ - Escape character for special characters in Makefile
# \\\ - Escape character for backslash in Makefile (Slightly confusing but necessary) !!Didn't Understand!!
# -D and DB_FILE are used to define DB_FILE preprocessor macro. (shouldn't contain space)

CC = gcc
# CFLAGS = Compiler Flags
# Warning controls: -Wall -Wextra
# Optimization level: -O2
# Preprocessor defines: -D...
# Include directories: -I...
CFLAGS = -Wall -O2
CFLAGS += -DDB_FILE=\"$(DBFILE)\" # Default DB_FILE if not specified during make command to override it.
TARGET = securePass
SRC = src/main.c src/auth.c src/storage.c
LIBS = -lpam -lpam_misc -largon2 -lcrypto
PAM_CONFIG = pam/securePass

# The DESTDIR variable is used to specify a temporary directory for installation.
# During packaging --- DESTDIR="$pkgdir" (set by makepkg)
# During testing	--- Set DESTDIR=/tmp/test manually while compiling using `make DESTDIR=/tmp/test`
# After install	--- There is no DESTDIR -> the files are now in real /usr/bin, /etc, etc.

# "makepkg" is the official Arch tool that:
# Reads PKGBUILD
# Creates a clean build environment
# Compiles project
# Installs the files into a temporary $pkgdir (DESTDIR)
# Packages everything into a .pkg.tar.zst file (Arch installable format) (AUR - Arch User Repository)

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# -mxxx - 3-digit number = owner, group, and others permissions.
# Example: 765 = owner can read/write/execute, group can read/write, others can read/execute. 4 = read
# /etc directory is for system configuration files, so it should not be writable by non-root users.
# pam folder is purely for authentication.
# `all` command only builds the binary file.
# `install` command installs the binary file and the PAM configuration file to their respective directories, not the whole project unless specified.
install:
	install -Dm755 $(TARGET) "$(DESTDIR)/usr/bin/$(TARGET)" 
	install -Dm644 $(PAM_CONFIG) "$(DESTDIR)/etc/pam.d/$(TARGET)"
uninstall:
	rm -f "$(DESTDIR)/usr/bin/$(TARGET)"
	rm -f "$(DESTDIR)/etc/pam.d/$(TARGET)"

clean:
	rm -f $(TARGET)

package: all install
	@echo "Package created successfully."