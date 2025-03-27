CC?=gcc
CXX?=g++
CFLAGS+=-g -O3 -std=gnu11 -march=native -Wno-psabi -I/opt/homebrew/Cellar/openssl@3/3.4.1/include
CPPFLAGS+=-I. -Isha3 -DNDEBUG -DHAVE_OPENSSL -DFAEST_EXPORT= -I/opt/homebrew/Cellar/openssl@3/3.4.1/include
LDFLAGS+="-L/opt/homebrew/Cellar/openssl@3/3.4.1/lib"
PKG_CONFIG_PATH+="/opt/homebrew/Cellar/openssl@3/3.4.1/lib/pkgconfig"
# How to solve -lcrypto not found:
# https://blog.csdn.net/fjh1997/article/details/106004642
SOURCES=$(filter-out randomness.c,$(wildcard *.c)) $(wildcard sha3/*.c)
EXECUTABLE_APITEST=tests/api_test
EXECUTABLE_NISTKAT=NIST-KATs/PQCgenKAT_sign
LIBFAEST=libfaest.a
NISTKAT_SOURCES=$(wildcard NIST-KATs/*.c)

all: $(LIBFAEST) $(EXECUTABLE_APITEST) $(EXECUTABLE_NISTKAT)

$(LIBFAEST): $(addsuffix .o, $(SOURCES))
	ar rcs $@ $^

%.c.o: %.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $< -o $@

$(EXECUTABLE_NISTKAT): CPPFLAGS+=-DHAVE_RANDOMBYTES
$(EXECUTABLE_NISTKAT): CFLAGS+=-Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-result

$(EXECUTABLE_APITEST): $(EXECUTABLE_APITEST).c.o $(LIBFAEST) randomness.c.o
	$(CC) $(CPPFLAGS) $(LDFLAGS) $^ -lcrypto -o $@

$(EXECUTABLE_NISTKAT): $(addsuffix .o, $(NISTKAT_SOURCES)) $(LIBFAEST) randomness.c
	$(CC) $(CPPFLAGS) $(LDFLAGS) $^ -lcrypto -o $@

clean:
	rm -f $(wildcard *.o) $(wildcard sha3/*.o) $(wildcard NIST-KATs/*.o) $(wildcard tests/*.o) \
		$(LIBFAEST) $(EXECUTABLE_APITEST) $(EXECUTABLE_NISTKAT)
