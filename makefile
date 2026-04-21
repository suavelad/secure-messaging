setup-env:
	python -m venv venv
	source venv/bin/activate
	pip install -r requirements.txt

start-server:
	uvicorn backend.main:app --reload

start-client:
	python main_client.py

stop-server:

reset:
	rm *.db
	make start-server


