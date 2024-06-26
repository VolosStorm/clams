# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS) -DETH_FATDB=1
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

CLAM_CONFIG_INCLUDES=-I$(builddir)/config
CLAM_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

CLAM_INCLUDES += -I$(srcdir)/secp256k1/include
CLAM_INCLUDES += $(UNIVALUE_CFLAGS)

LIBCLAM_SERVER=libclam_server.a
LIBCLAM_COMMON=libclam_common.a
LIBCLAM_CONSENSUS=libclam_consensus.a
LIBCLAM_CLI=libclam_cli.a
LIBCLAM_UTIL=libclam_util.a
LIBCLAM_CRYPTO=crypto/libclam_crypto.a
LIBCLAMQT=qt/libclamqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

if ENABLE_ZMQ
LIBCLAM_ZMQ=libclam_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBCLAMCONSENSUS=libclamconsensus.la
endif
if ENABLE_WALLET
LIBCLAM_WALLET=libclam_wallet.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBCLAM_CRYPTO) \
  $(LIBCLAM_UTIL) \
  $(LIBCLAM_COMMON) \
  $(LIBCLAM_CONSENSUS) \
  $(LIBCLAM_SERVER) \
  $(LIBCLAM_CLI) \
  $(LIBCLAM_WALLET) \
  $(LIBCLAM_ZMQ)

lib_LTLIBRARIES = $(LIBCLAMCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_CLAMD
  bin_PROGRAMS += clamd
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += clam-cli clam-tx
endif

.PHONY: FORCE check-symbols check-security
# clam core #
CLAM_CORE_H = \
  addrdb.h \
  addrman.h \
  base58.h \
  bloom.h \
  blockencodings.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clamspeech.h \
  clamour.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  httprpc.h \
  httpserver.h \
  indirectmap.h \
  init.h \
  key.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  pos.h \
  protocol.h \
  random.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/register.h \
  scheduler.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/ismine.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  txoffset.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utiltime.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/coincontrol.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libclam_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between clamd and clam-qt
libclam_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libclam_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libclam_server_a_SOURCES = \
  addrdb.cpp \
  addrman.cpp \
  bloom.cpp \
  blockencodings.cpp \
  chain.cpp \
  checkpoints.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  pos.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  timedata.cpp \
  script/ismine.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(CLAM_CORE_H)

if ENABLE_ZMQ
libclam_zmq_a_CPPFLAGS = $(CLAM_INCLUDES) $(ZMQ_CFLAGS)
libclam_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libclam_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between clamd and clam-qt, but only linked
# when wallet enabled
libclam_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES)
libclam_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libclam_wallet_a_SOURCES = \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  policy/rbf.cpp \
  $(CLAM_CORE_H)

# crypto primitives library
crypto_libclam_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_CONFIG_INCLUDES)
crypto_libclam_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libclam_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h

# consensus: shared between all executables that validate any consensus rules.
libclam_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES)
libclam_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libclam_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  bignum.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  netaddress.cpp \
  netaddress.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/bitcoinconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  timedata.cpp \
  timedata.h \
  tinyformat.h \
  ui_interface.cpp \
  ui_interface.h \
  warnings.cpp \
  warnings.h \
  crypto/scrypt.cpp \
  crypto/scrypt-sse2.cpp \
  crypto/scrypt.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h

# common: shared between clamd, and clam-qt and non-server tools
libclam_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES)
libclam_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libclam_common_a_SOURCES = \
  amount.cpp \
  base58.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  protocol.cpp \
  scheduler.cpp \
  script/sign.cpp \
  script/standard.cpp \
  warnings.cpp \
  $(CLAM_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libclam_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES)
libclam_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libclam_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(CLAM_CORE_H)

if GLIBC_BACK_COMPAT
libclam_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: shared between clam-cli and clam-qt
libclam_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES)
libclam_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libclam_cli_a_SOURCES = \
  rpc/client.cpp \
  $(CLAM_CORE_H)

nodist_libclam_util_a_SOURCES = $(srcdir)/obj/build.h
#

# clamd binary #
clamd_SOURCES = bitcoind.cpp
clamd_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES)
clamd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
clamd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
clamd_SOURCES += bitcoind-res.rc
endif

clamd_LDADD = \
  $(LIBCLAM_SERVER) \
  $(LIBCLAM_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBCLAM_UTIL) \
  $(LIBCLAM_WALLET) \
  $(LIBCLAM_ZMQ) \
  $(LIBCLAM_CONSENSUS) \
  $(LIBCLAM_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

clamd_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)

# clam-cli binary #
clam_cli_SOURCES = bitcoin-cli.cpp
clam_cli_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES) $(EVENT_CFLAGS)
clam_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
clam_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
clam_cli_SOURCES += bitcoin-cli-res.rc
endif

clam_cli_LDADD = \
  $(LIBCLAM_CLI) \
  $(LIBUNIVALUE) \
  $(LIBCLAM_UTIL) \
  $(LIBCLAM_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV)

clam_cli_LDADD += $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# clam-tx binary #
clam_tx_SOURCES = bitcoin-tx.cpp
clam_tx_CPPFLAGS = $(AM_CPPFLAGS) $(CLAM_INCLUDES)
clam_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
clam_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
clam_tx_SOURCES += bitcoin-tx-res.rc
endif

clam_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBCLAM_COMMON) \
  $(LIBCLAM_UTIL) \
  $(LIBCLAM_CONSENSUS) \
  $(LIBCLAM_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

clam_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/bitcoinconsensus.h
libclamconsensus_la_SOURCES = $(crypto_libclam_crypto_a_SOURCES) $(libclam_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libclamconsensus_la_SOURCES += compat/glibc_compat.cpp
endif


if TARGET_WINDOWS 
libclamconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS) $(LIBCLAM_UTIL)
libclamconsensus_la_LIBADD = $(LIBSECP256K1) $(CRYPTO_LIBS) $(BOOST_LIBS)
libclamconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_CLAM_INTERNAL $(SSL_CFLAGS) $(BOOST_CPPFLAGS)
else
if TARGET_DARWIN
libclamconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS) $(LIBCLAM_UTIL)
libclamconsensus_la_LIBADD = $(LIBSECP256K1) $(CRYPTO_LIBS) $(BOOST_LIBS)
libclamconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_CLAM_INTERNAL $(SSL_CFLAGS) $(BOOST_CPPFLAGS)
else 
libclamconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libclamconsensus_la_LIBADD = $(LIBSECP256K1) $(CRYPTO_LIBS)
libclamconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_CLAM_INTERNAL $(SSL_CFLAGS)
endif
endif
libclamconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = $(CTAES_DIST)

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f a/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
