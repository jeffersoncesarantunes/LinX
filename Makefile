CC=gcc
CFLAGS=-Iinclude -Wall -Wextra -Wpedantic -O2 -std=c99 -D_DEFAULT_SOURCE \
       -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE \
       -Wformat -Wformat-security -Wconversion -Wsign-conversion -Wshadow
LDFLAGS=-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code
TARGET=linx
SRC=src/main.c src/correlate.c src/report.c

.PHONY: all clean test install install-man uninstall lint docker debug

all: $(TARGET)

$(TARGET): $(SRC) include/correlate.h
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)
	@strip $(TARGET)
	@echo "✅ Build successful."
	@mkdir -p reports

debug: CFLAGS += -g -O0 -DDEBUG
debug: LDFLAGS += -g
debug: $(TARGET)
	@echo "🔧 Debug build."

MANDIR ?= $(DESTDIR)/usr/local/share/man/man1

install: $(TARGET) install-man
	@install -m 0755 -d $(DESTDIR)/usr/local/bin
	@install -m 0755 $(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)
	@echo "✅ Installed to $(DESTDIR)/usr/local/bin/$(TARGET)"

install-man:
	@install -m 0755 -d $(MANDIR)
	@install -m 644 man/linx.1 $(MANDIR)/linx.1
	@echo "  📄 Installed man page to $(MANDIR)"

uninstall:
	@rm -f $(DESTDIR)/usr/local/bin/$(TARGET)
	@rm -f $(MANDIR)/linx.1
	@-rmdir $(MANDIR) 2>/dev/null; true
	@echo "🗑  Uninstalled."

test: $(TARGET)
	@echo "🧪 Running tests..."
	@bash tests/run_tests.sh

lint:
	@which cppcheck >/dev/null 2>&1 && \
		cppcheck --enable=all --std=c99 --suppress=missingIncludeSystem \
		--error-exitcode=1 -Iinclude $(SRC) || \
		true
	@which scan-build >/dev/null 2>&1 && \
		scan-build --status-bugs make clean all 2>/dev/null || \
		true

docker:
	@docker build -t linx:latest .
	@echo "🐳 Docker image built: linx:latest"

clean:
	@rm -f $(TARGET)
	@rm -rf build/
	@echo "🧹 Clean."
