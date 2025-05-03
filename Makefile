# Read config.mk for paths
include config.mk

# Desktop File Path
DESKTOP_FILE = bastix.desktop
ICON_FILE = bastix.png
DESKTOP_INSTALL_DIR = $(PREFIX)/share/applications
ICON_INSTALL_DIR = $(PREFIX)/share/icons/hicolor/64x64/apps

install:
	@echo "Installing Bastix..."

	# Install the Python script
	mkdir -p $(SHAREDIR)
	install -Dm644 bastix.py $(SHAREDIR)/bastix.py

	# Install the launcher script
	sed "s@PYTHON_SCRIPT=.*@PYTHON_SCRIPT=$(SHAREDIR)/bastix.py@" bastix > $(BINDIR)/bastix
	chmod +x $(BINDIR)/bastix

	# Install the .desktop file
	mkdir -p $(DESKTOP_INSTALL_DIR)
	install -Dm644 $(DESKTOP_FILE) $(DESKTOP_INSTALL_DIR)/$(DESKTOP_FILE)

	# Install the icon
	mkdir -p $(ICON_INSTALL_DIR)
	install -Dm644 $(ICON_FILE) $(ICON_INSTALL_DIR)/$(ICON_FILE)

	@echo "Install complete. You can now find Bastix in the application menu."

uninstall:
	@echo "Uninstalling Bastix..."
	rm -f $(BINDIR)/bastix
	rm -rf $(SHAREDIR)
	rm -f $(DESKTOP_INSTALL_DIR)/$(DESKTOP_FILE)
	rm -f $(ICON_INSTALL_DIR)/$(ICON_FILE)
	@echo "Uninstall complete."

clean:
	@echo "Cleaning temporary files..."
	rm -rf config.mk
	@echo "Clean complete."