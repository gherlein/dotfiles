SHELL := /bin/bash
STACK_DIR := $(HOME)/.config/govirt/stacks/devbox
HOST_SETUP_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))host-setup

.PHONY: help host-setup install-multipass install-nfs setup-paths install-export-gen export-nfs enable-nfs ufw-allow create-vm delete-vm ssh-vm status-vm

help:
	@echo "devbox VM management"
	@echo ""
	@echo "Host setup (run once, before creating the VM):"
	@echo "  make host-setup        Run all host setup steps in sequence"
	@echo "  make install-multipass Install Multipass (via snap)"
	@echo "  make install-nfs       Install nfs-kernel-server"
	@echo "  make setup-paths       Install /etc/host-shadow-paths"
	@echo "  make install-export-gen Install /usr/local/bin/shadow-export-gen"
	@echo "  make export-nfs        Run shadow-export-gen to (re)generate /etc/exports"
	@echo "  make enable-nfs        Enable and start nfs-kernel-server"
	@echo "  make ufw-allow         Allow NFS through ufw (if ufw is active)"
	@echo ""
	@echo "VM lifecycle:"
	@echo "  make create-vm         govirt create devbox"
	@echo "  make delete-vm         govirt destroy devbox"
	@echo "  make ssh-vm            govirt ssh devbox"
	@echo "  make status-vm         govirt status devbox"

# --------------------------------------------------------------------------
# Host setup: all steps
# --------------------------------------------------------------------------
host-setup: install-multipass install-nfs setup-paths install-export-gen export-nfs enable-nfs
	@echo ""
	@echo "Host setup complete. Run 'make ufw-allow' if ufw is active."
	@echo "Then run 'make create-vm' to launch the VM."

install-multipass:
	@if command -v multipass >/dev/null 2>&1; then \
	    echo "multipass already installed: $$(multipass version 2>/dev/null | head -1)"; \
	else \
	    echo "Installing Multipass via snap..."; \
	    sudo apt-get install -y snapd; \
	    sudo snap install multipass; \
	fi

install-nfs:
	sudo apt-get update -qq
	sudo apt-get install -y nfs-kernel-server

setup-paths:
	sudo cp $(HOST_SETUP_DIR)/host-shadow-paths /etc/host-shadow-paths
	@echo "Installed /etc/host-shadow-paths from repo template"

install-export-gen:
	sudo cp $(HOST_SETUP_DIR)/shadow-export-gen /usr/local/bin/shadow-export-gen
	sudo chmod +x /usr/local/bin/shadow-export-gen

export-nfs:
	sudo shadow-export-gen

enable-nfs:
	sudo systemctl enable --now nfs-kernel-server
	sudo systemctl status nfs-kernel-server --no-pager

ufw-allow:
	$(eval VM_NETWORK := $(shell multipass list --format json 2>/dev/null \
	    | python3 -c "import sys,json; vms=json.load(sys.stdin)['list']; \
	      r=[v for v in vms if v['state']=='Running']; \
	      ip=r[0]['ipv4'][0] if r and r[0]['ipv4'] else ''; \
	      print('.'.join(ip.split('.')[:3])+'.0/24' if ip else '')" 2>/dev/null || echo ""))
	@if [ -z "$(VM_NETWORK)" ]; then \
	    echo "Could not detect VM network. Start the VM first, or pass it manually:"; \
	    echo "  sudo ufw allow from <VM_NETWORK>/24 to any port nfs"; \
	    echo "  sudo ufw allow from <VM_NETWORK>/24 to any port 111"; \
	else \
	    sudo ufw allow from $(VM_NETWORK) to any port nfs; \
	    sudo ufw allow from $(VM_NETWORK) to any port 111; \
	    sudo ufw reload; \
	    echo "ufw rules added for $(VM_NETWORK)"; \
	fi

# --------------------------------------------------------------------------
# VM lifecycle
# --------------------------------------------------------------------------
create-vm:
	govirt create devbox

delete-vm:
	govirt destroy devbox

ssh-vm:
	govirt ssh devbox

status-vm:
	govirt status devbox
