# To create a .pkg.tar.zst for public installation
# Usage: makepkg -si
# For more information, see 'man PKGBUILD'.

# Maintainer: Sanavi Sonwane <sanvi.harnale@gmail.com>
pkgname='securePass' # '-bzr', '-git', '-hg' or '-svn'
pkgver=1.0.0
pkgrel=1
pkgdesc="Authenticated Encryption based Password Manager"
arch=('x86_64')
url="https://github.com/ISanviI/securePass"
license=('GPL')
depends=('pam' 'argon2' 'openssl')
makedepends=('git' 'gcc')
provides=("$pkgname")
conflicts=("$pkgname")
install=$pkgname.install
source=("$pkgname-$pkgver::https://raw.githubusercontent.com/ISanviI/securePass/main/bin/securePass")
noextract=("$pkgname-$pkgver")
sha256sums=('SKIP')

pkgver() {
  cd "$pkgname"
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short=7 HEAD)"
}

build() {
  cd "$srcdir/$pkgname-$pkgver"
  make
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  make DESTDIR="$pkgdir" install
}