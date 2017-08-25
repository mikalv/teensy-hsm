.PHONY: clean test-sha1 test-aes

clean: test-runner
	@rm -f $<

test-crc16: crc16.cpp test/test-crc16.cpp
	@g++ -I. -I./test $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-sha1: sha1.cpp test/test-sha1.cpp
	@g++ -I. -I./test $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-sha1-hmac: sha1.cpp sha1-hmac.cpp test/test-sha1-hmac.cpp
	@g++ -I. -I./test $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-aes: aes.cpp test/test-aes.cpp
	@g++ -I. -I./test $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-aes-drbg: aes.cpp aes-drbg.cpp test/test-aes-drbg.cpp
	@g++ -I. -I./test $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-aes-cbc: aes.cpp aes-cbc.cpp test/test-aes-cbc.cpp
	@g++ -I. -I./test $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-aes-ccm: aes.cpp aes-ccm.cpp test/test-aes-ccm.cpp
	@g++ -I. -I./test $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-storage: sha1.cpp sha1-hmac.cpp aes.cpp aes-ccm.cpp aes-cbc.cpp storage.cpp util.cpp test/test-storage.cpp test/debug.cpp
	@g++ -I. -I./test $(USER_DEFINES) -DDEBUG_STORAGE $^ -o test-runner && ./test-runner

