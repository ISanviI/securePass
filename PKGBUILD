# PKGBUILD (Alternate - makepkg)
# To create a .pkg.tar.zst for public installation
pkgname=securePass
pkgver=1.0
pkgrel=1
arch=('x86_64')
pkgdesc="A simple secure encrypted Password Manager CLI tool written in C."
license=('MIT')
depends=()
makedepends=('gcc')
source=()
md5sums=()

build() {
  make
}

package() {
  make DESTDIR="$pkgdir" install
}