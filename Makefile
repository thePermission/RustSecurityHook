NAME ?= main

.PHONY: fmt fmt-check clippy test ci bench bench-save bench-compare install

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

ci: fmt-check clippy test

bench:
	cargo bench --bench hook 2>/dev/null

bench-save:
	cargo bench --bench hook -- --save-baseline $(NAME) 2>/dev/null
	@echo "Baseline '$(NAME)' saved. Compare later with: make bench-compare NAME=$(NAME)"

bench-compare:
	cargo bench --bench hook -- --baseline $(NAME) 2>/dev/null

install:
	cargo install --path . --root ~/.local
