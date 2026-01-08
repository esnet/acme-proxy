APP_NAME = step-ca
VERSION = v0.29.0
UPSTREAM = https://github.com/smallstep/certificates.git

SUDO := $(shell if [ $$(id -u) -ne 0 ]; then echo "$(SUDO)"; else echo ""; fi)

# Targets
.PHONY: all clean check-deps dev build

default: build

clean:
	@echo "🧹 Cleaning build cache..."
	go clean -cache
	rm -f step-ca
	rm -rf db
	rm -rf .build

check-deps:
	@echo "🔍 Checking for libpcsclite-dev dependency..."
	@OS_NAME=$$(uname -s); \
	if [ "$$OS_NAME" = "Darwin" ]; then \
		echo "🍏 found macOS - Skipping dependency check"; \
	elif [ -f /etc/os-release ]; then \
		. /etc/os-release; \
		if echo "$$ID" | grep -Eqi 'ubuntu|debian'; then \
			if ! dpkg -s libpcsclite-dev >/dev/null 2>&1; then \
				echo "📦 Installing libpcsclite-dev on Debian/Ubuntu..."; \
				$(SUDO) apt-get update && $(SUDO) apt-get install -y libpcsclite-dev; \
			else \
				echo "📦 libpcsclite-dev already installed."; \
			fi; \
		elif echo "$$ID" | grep -Eqi 'rhel|rocky|centos'; then \
			if ! rpm -q pcsc-lite-devel >/dev/null 2>&1; then \
				echo "📦 Installing pcsc-lite-devel on Rocky/RHEL..."; \
				$(SUDO) dnf install -y pcsc-lite-devel; \
			else \
				echo "📦 pcsc-lite-devel already installed."; \
			fi; \
		else \
			echo "⚠️ Unknown Linux distribution: $$ID. You may need to install some dependencies manually."; \
		fi; \
	else \
		echo "Cannot detect OS. /etc/os-release not found."; \
		exit 1; \
	fi

dev: clean check-deps
	@echo "⬇️ Downloading dependencies to create dev environment..."
	git clone --branch $(VERSION) --depth 1 $(UPSTREAM) .build/certificates/
	rm -rf .build/certificates/server && cp -r ./hack/server .build/certificates/server
	mkdir db
	go mod tidy
	@echo "✅ Ready"

build: clean check-deps
	@echo "⚙️ Building ACME proxy with Step CA..."
	mkdir .build
	git clone --branch $(VERSION) --depth 1 $(UPSTREAM) .build/certificates/
	rm -rf .build/certificates/server && cp -r ./hack/server .build/certificates/server
	mkdir db
	go build -v -o $(APP_NAME) .
	@echo "✅ Done"
