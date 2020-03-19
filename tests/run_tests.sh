#!/bin/bash

RED='\033[31;1m'
NC='\033[0m' # No Color

OUTPUT_FILE=/tmp/compiler_output
COMPILER=./compiler

for file in ./tests/valid/*; do
	if ! $COMPILER $file >& $OUTPUT_FILE; then
		echo -e "${RED}Test failed: ${file}${NC}"
		cat $OUTPUT_FILE
	fi
done

for file in ./tests/invalid/*; do
	if $COMPILER $file >& $OUTPUT_FILE; then
		echo -e "${RED}Test failed: ${file}${NC}"
		cat $OUTPUT_FILE
	fi
done
