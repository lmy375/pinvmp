#!/bin/sh

# DEFAULT_PATH="D:/paper/papers/test_asm/test_pin/base64_vmp/base64.vmp_1.81_demo.exe"
DEFAULT_PATH="D:/paper/papers/test_asm/test_llvm/all_op/all_op2.vmp_1.81.exe"

if [ "$1" = "make" ]; then
    make TARGET=ia32
    ../../../pin.exe  -t obj-ia32/MyPinTool.dll -- $DEFAULT_PATH
elif [ "$1" = "clean" ]; then
    rm *.dump *.info *.trace *.log
elif [ "$1" = "" ]; then
    ../../../pin.exe  -t obj-ia32/MyPinTool.dll -- $DEFAULT_PATH
else
    ../../../pin.exe  -t obj-ia32/MyPinTool.dll -- $1
fi