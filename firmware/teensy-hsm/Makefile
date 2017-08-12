.PHONY: clean test-sha1

clean: test-runner
	@rm -f $<

test-sha1: sha1.cpp sha1.h 
	@g++ -DUNIT_TEST sha1.cpp -o test-runner && ./test-runner
