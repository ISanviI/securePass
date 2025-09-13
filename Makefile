# Makefile
# TODO - chown root:securepass securepass.db 	chmod 600 securepass.db
# // Using mlock() or libsodium sodium_mlock() on sensitive buffers to avoid data swap across memory.
# // Use a proper JSON parser (e.g., jsmn or cJSON) rather than the ad-hoc parser used here.


# Typical locations used by make install (Makefile):
# Executables → /usr/local/bin/
# Libraries → /usr/local/lib
# Headers → /usr/local/include/
# Config/docs → /usr/local/etc/ and /usr/local/share/

# Current make command - 
# 	Testing ---> make install DESTDIR=/tmp/pkg CFLAGS="$(CFLAGS) -DDB_FILE=\\\"$(DESTDIR)$(DBFILE)\\\""
# 							 make clean && make install DESTDIR="/tmp/test" CFLAGS="-Wall -O2 -DDB_FILE='\"<DESTDIR>/securePass.db\"'"
# 							 sudo ln -s <DESTDIR>/etc/pam.d/securePass /etc/pam.d/securePass (To create a symbolic link for testing)
# 							 sudo rm /etc/pam.d/securePass (To remove symlink)
# 	Installation ---> make install
# 	Execution ---> ./securePass or securePass
# \ - Escape character for special characters in Makefile
# \\\ - Escape character for backslash in Makefile (Slightly confusing but necessary) !!Didn't Understand!!
# -D and DB_FILE are used to define DB_FILE preprocessor macro. (shouldn't contain space)

# CFLAGS = Compiler Flags
# Warning controls: -Wall -Wextra
# Optimization level: -O2
# Preprocessor defines: -D...
# Include directories: -I...
CC = gcc
AUTH_ETC_PATH ?= /etc/securePass/auth.conf
DBFILE ?= /var/lib/securePass/securePass.db
CFLAGS = -Wall -O2
CFLAGS += -DDB_FILE=\"$(DBFILE)\" # Default DB_FILE if not specified during make command to override it.
TARGET = securePass
SRC = src/main.c src/auth.c src/storage.c src/crypto.c
LIBS = -lpam -lpam_misc -largon2 -lcrypto
PAM_CONFIG = pam/securePass

# The DESTDIR variable is used to specify a temporary directory for installation.
# During packaging --- DESTDIR="$pkgdir" (set by makepkg)
# During testing	--- Set DESTDIR=/tmp/test manually while compiling using `make DESTDIR=/tmp/test`
# After install	--- There is no DESTDIR -> the files are now in real /usr/bin, /etc, etc.

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# -mxxx - 3-digit number = owner, group, and others permissions.
# Example: 765 = owner can read/write/execute, group can read/write, others can read/execute. 4 = read
# /etc directory is for system configuration files, so it should not be writable by non-root users.
# pam folder is purely for authentication.
# `all` command only builds the binary file (default).
# `install` command installs the binary file and the PAM configuration file to their respective directories, not the whole project unless specified.
install:all # Added `all` to ensure binary is built before installation.
	install -Dm755 $(TARGET) "$(DESTDIR)/usr/bin/$(TARGET)" 
	install -Dm644 $(PAM_CONFIG) "$(DESTDIR)/etc/pam.d/$(TARGET)"

clean:
	rm -f $(TARGET)

package: all install
	@echo "Package created successfully."