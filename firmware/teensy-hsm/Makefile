.PHONY: clean test-sha1 test-aes

clean: test-runner
	@rm -f $<

test-sha1: sha1.cpp sha1.h 
	@g++ -I. sha1.cpp test/test-sha1.cpp -o test-runner && ./test-runner

test-aes: aes.cpp aes.h
	@g++ -I. aes.cpp test/test-aes.cpp -o test-runner && ./test-runner
