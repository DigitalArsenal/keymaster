#!/usr/bin/env sh

# Based on code from https://github.com/TrueBitFoundation/wasm-ports/blob/master/openssl.sh

OPENSSL_VERSION=1.1.1j
PREFIX=$(pwd)

DIRECTORY="openssl"
#-${OPENSSL_VERSION}"
DEST_FILE="openssl-${OPENSSL_VERSION}.tar.gz"
echo $DEST_FILE
if [ ! -f "$DEST_FILE" ]; then
  echo "Download source code"
  curl https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz -o $DEST_FILE
fi

if [ ! -d "openssl-${OPENSSL_VERSION}" ]; then
  echo "UNCOMPRESSING ${DEST_FILE}"
  tar xf $DEST_FILE
fi

rm -R openssl
mv openssl-${OPENSSL_VERSION} openssl

if [ -d "patch-${OPENSSL_VERSION}" ]; then
  cd patch-${OPENSSL_VERSION}
  find . -type f | cpio -pvduml ../${DIRECTORY}
  cd ../
fi

cd ${DIRECTORY}

echo "Configure"
make clean

./Configure linux-x86-clang -no-dso -no-ui-console -no-dynamic-engine -no-threads -no-tests -no-asm -static -no-sock -no-afalgeng -DNO_SYSLOG=0 -D_WASI_EMULATED_MMAN  -D_WASI_EMULATED_SIGNAL -DOPENSSL_SYS_NETWARE -DSIG_DFL=0 -DSIG_IGN=0 -DHAVE_FORK=0 -DOPENSSL_NO_AFALGENG=1 -DCRYPTO_TDEBUG=1 --with-rand-seed=getrandom || exit $?
sed -i -e "s/CNF_EX_LIBS=/CNF_EX_LIBS=-lwasi-emulated-mman /g" Makefile

sed -i 's|^CROSS_COMPILE.*$|CROSS_COMPILE=|g' Makefile
sed -i 's|^CFLAGS=.*$|CFLAGS=-Wall -O3 -static -Wl,-v -fomit-frame-pointer -I/opt/wasi-sysroot/include -stdlib=libc++ --target=wasm32-unknown-wasi --sysroot=/opt/wasi-sysroot -ftls-model=local-exec -v -lwasi-emulated-signal|' Makefile
sed -i 's|^RANLIB=.*$|RANLIB=llvm-ranlib|' Makefile
sed -i 's|^AR=.*$|AR=llvm-ar|' Makefile

echo "Build"
make clean
make -j12 build_generated
make -j12 libcrypto.a #libssl.a apps/openssl

rm -rf ${PREFIX}/include
mkdir -p ${PREFIX}/include
cp -R include/openssl ${PREFIX}/include

echo "Copying libcrypto.a ..."

cp libcrypto.a ../../lib/wasm/libcrypto.a

echo "Done"
