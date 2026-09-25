.PHONY: test lint bench-up demo

test:
	uv run pytest

lint:
	uv run ruff check src/ tests/ experiments/
	uv run mypy

bench-up:
	cd bench && uv run uvicorn tracebench.main:app --port 9000

demo:
	@echo "1. In another terminal, run: make bench-up"
	@echo "2. Then, with GROQ_API_KEY set in .env:"
	@echo "   uv run python experiments/eval-run-1/run_full_evaluation.py"
