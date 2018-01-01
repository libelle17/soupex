#!/bin/bash
P=/root/rogerj/roger-router-1.9.3
ctags *.c $(find .. -name "*.h" -o -name "*.c") $(find $P -name "*.h" -o -name "*.c")
vi test.c $P/roger-cli/main_cli.c get.c $(find $P/libroutermanager/plugins/fritzbox -name "*.h" -o -name "*.c") $(find $P -name "*.c") -p
