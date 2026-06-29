# husk — read-only ELF / permissions / capability inspector
#
# Ships a CLI (husk) and a GTK4 GUI (husk-gui) together.
#
#   make            build both binaries
#   make cli        build only the CLI
#   make gui        build only the GUI
#   make install    install both globally, plus the icon and .desktop entry,
#                   and refresh the icon/desktop caches (taskbar gets the icon)
#   make uninstall  remove everything this Makefile installed

CXX        ?= g++
CC         ?= cc
CXXFLAGS   ?= -std=c++17 -O2 -Wall -Wextra
CFLAGS     ?= -O2 -Wall -Wextra
GTK_CFLAGS  = $(shell pkg-config --cflags gtk4)
GTK_LIBS    = $(shell pkg-config --libs gtk4)

PREFIX     ?= /usr/local
BINDIR      = $(PREFIX)/bin
# Desktop entry and icons go under /usr/share so the icon theme and taskbar
# always find them, regardless of whether /usr/local/share is in XDG_DATA_DIRS.
DESKTOPDIR  = /usr/share/applications
ICONDIR     = /usr/share/icons/hicolor
PNGDIR      = $(ICONDIR)/256x256/apps
SVGDIR      = $(ICONDIR)/scalable/apps

ICON        = husk
CLI         = husk
GUI         = husk-gui

all: $(CLI) $(GUI)

$(CLI): husk.cpp
	$(CXX) $(CXXFLAGS) husk.cpp -o $(CLI)

$(GUI): husk-gui.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) husk-gui.c -o $(GUI) $(GTK_LIBS)

cli: $(CLI)
gui: $(GUI)

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(CLI) $(DESTDIR)$(BINDIR)/$(CLI)
	install -m 0755 $(GUI) $(DESTDIR)$(BINDIR)/$(GUI)
	install -d $(DESTDIR)$(PNGDIR) $(DESTDIR)$(SVGDIR)
	install -m 0644 $(ICON).png $(DESTDIR)$(PNGDIR)/$(ICON).png
	install -m 0644 $(ICON).svg $(DESTDIR)$(SVGDIR)/$(ICON).svg
	install -d $(DESTDIR)$(DESKTOPDIR)
	install -m 0644 $(ICON).desktop $(DESTDIR)$(DESKTOPDIR)/$(ICON).desktop
	-gtk-update-icon-cache -f -t $(DESTDIR)$(ICONDIR) 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(DESKTOPDIR) 2>/dev/null || true
	@echo "Installed husk (CLI) and husk-gui (GUI). Look for \"husk\" in your menu / taskbar."

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(CLI)
	rm -f $(DESTDIR)$(BINDIR)/$(GUI)
	rm -f $(DESTDIR)$(PNGDIR)/$(ICON).png
	rm -f $(DESTDIR)$(SVGDIR)/$(ICON).svg
	rm -f $(DESTDIR)$(DESKTOPDIR)/$(ICON).desktop
	-gtk-update-icon-cache -f -t $(DESTDIR)$(ICONDIR) 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(DESKTOPDIR) 2>/dev/null || true

clean:
	rm -f $(CLI) $(GUI)

.PHONY: all cli gui install uninstall clean
