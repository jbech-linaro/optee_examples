global-incdirs-y += include
srcs-y += gatekeeper_ta.c
# FIXME: Remove the -Wno-unused-function when all functions have been implemented
cflags-y += -Wno-unused-function
