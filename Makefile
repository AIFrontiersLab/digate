.PHONY: demo test api install

install:
	python -m pip install -r requirements.txt

demo:
	python -c "from main import demo; demo()"

test:
	pytest -q

api:
	uvicorn main:app --host 0.0.0.0 --port 8000
