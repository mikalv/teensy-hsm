.PHONY: clean test-sha1 test-aes

clean: test-runner
	@rm -f $<

test-sha1: sha1.cpp test/test-sha1.cpp
	@g++ -I. $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-sha1-hmac: sha1.cpp sha1-hmac.cpp test/test-sha1-hmac.cpp
	@g++ -I. $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-aes: aes.cpp test/test-aes.cpp
	@g++ -I. $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-aes-cbc: aes.cpp aes-cbc.cpp test/test-aes-cbc.cpp
	@g++ -I. $(USER_DEFINES) $^ -o test-runner && ./test-runner

test-aes-ccm: aes.cpp aes-ccm.cpp test/test-aes-ccm.cpp
	@g++ -I. $(USER_DEFINES) $^ -o test-runner && ./test-runner
