NAME ?= main

bench:
	cargo bench --bench hook 2>/dev/null

bench-save:
	cargo bench --bench hook -- --save-baseline $(NAME) 2>/dev/null
	@echo "Baseline '$(NAME)' saved. Compare later with: make bench-compare NAME=$(NAME)"

bench-compare:
	cargo bench --bench hook -- --baseline $(NAME) 2>/dev/null
