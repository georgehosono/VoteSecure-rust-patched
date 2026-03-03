################################################################################
# Makefile to conveniently run Cryptol model verification                      #
# @author Frank Zeyda (frank.zeyda@freeandfair.us)                             #
# @copyright Free & Fair 2025                                                  #
# @version 0.2                                                                 #
################################################################################

# Default target: help
default: help

# Display a brief help page listing possible commands/targets.
help:
	@echo "List of Possible make commands/targets:"
	@echo "make        - runs the default command (make help)"
	@echo "make all    - executes all commands (verify)"
	@echo "make verify - syntax and type-checks all cryptol modules;"
	@echo "              also runs docstring commands where present,"
	@echo "              namely to carry out property verification"
	@echo "make clean  - cleans up all dynamically generated files"
	@echo "make help   - displays this help page"

# Executes all targets.
all: verify

# Executes Cryptol verification tasks on all source files.
verify:
	$(info [info] performing syntax&type checking, and verification ...)
	cryptol --project "$(CURDIR)"

# Cleans up all dynamically generated files, including caches.
# Currently a no-op; retained for forward compatibility.
clean:
	@true

# List of phony targets
.PHONY: default help all verify clean
