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
install=${pkgname}.install
source=("$pkgname-$pkgver.tar.gz::https://github.com/ISanviI/securePass/archive/refs/tags/v$pkgver.tar.gz")
noextract=("$pkgname-$pkgver")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  make
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  make DESTDIR="$pkgdir" install
}