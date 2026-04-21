# ── Backend ────────────────────────────────────────────────────────────────────

# Create a Python virtual environment and install all backend dependencies.
setup-backend:
	python3 -m venv venv
	venv/bin/pip install --upgrade pip
	venv/bin/pip install -r backend/requirements.txt

# Start the FastAPI relay server (hot-reload enabled for development).
# Access the interactive API docs at http://localhost:8000/docs
start-backend:
	DEBUG=true venv/bin/uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Wipe the SQLite database and restart fresh.
reset-backend:
	rm -f secure_messenger.db
	make start-backend

# ── Mobile (Flutter) ───────────────────────────────────────────────────────────

# One-time setup: scaffold Android + iOS platform directories and fetch packages.
# Run this once after cloning / before the first `make run-mobile`.
setup-mobile:
	cd mobile && flutter create . --project-name secure_messenger --platforms android,ios
	cd mobile && flutter pub get

# Fetch / refresh Flutter package dependencies (run after editing pubspec.yaml).
flutter-deps:
	cd mobile && flutter pub get

# Launch the app on a connected device or running emulator.
run-mobile:
	cd mobile && flutter run

# Run Flutter static analysis.
lint-mobile:
	cd mobile && flutter analyze

# Run Flutter unit tests.
test-mobile:
	cd mobile && flutter test

# ── Quick API smoke-test (curl) ────────────────────────────────────────────────
# Requires the backend to be running. Replace USERNAME / PASSWORD as needed.

smoke-test:
	@echo "\n--- Register user alice ---"
	curl -s -X POST http://localhost:8000/auth/register \
	  -H "Content-Type: application/json" \
	  -H "X-Nonce: $$(python3 -c 'import uuid; print(uuid.uuid4())')" \
	  -H "X-Timestamp: $$(date +%s)" \
	  -d '{"username":"alice","password":"password123","identity_key_pub":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pre_key_pub":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' | python3 -m json.tool
	@echo "\n--- Login as alice ---"
	curl -s -X POST http://localhost:8000/auth/login \
	  -H "Content-Type: application/json" \
	  -H "X-Nonce: $$(python3 -c 'import uuid; print(uuid.uuid4())')" \
	  -H "X-Timestamp: $$(date +%s)" \
	  -d '{"username":"alice","password":"password123"}' | python3 -m json.tool
