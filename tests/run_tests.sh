#!/bin/bash

RED='\033[31;1m'
GREEN='\033[32;1m'
NC='\033[0m' # No Color

OUTPUT_FILE=/tmp/compiler_output
COMPILER=./compiler
TESTS_PASSED=1

for file in ./tests/valid/*; do
	if ! $COMPILER $file >& $OUTPUT_FILE; then
		echo -e "${RED}Test failed: ${file}${NC}"
		TESTS_PASSED=0
		cat $OUTPUT_FILE
	fi
done

for file in ./tests/invalid/*; do
	if $COMPILER $file >& $OUTPUT_FILE; then
		echo -e "${RED}Test failed: ${file}${NC}"
		TESTS_PASSED=0
	fi
	cat $OUTPUT_FILE
done

if [ "$TESTS_PASSED" -eq 1 ]; then
	echo -e "${GREEN}Tests passed${NC}"
else
	echo -e "${RED}Tests failed${NC}"
fi
