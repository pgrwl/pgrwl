grep -rn "\.Info\|\.Warn\|\.Error\|\.Debug" /home/os/Desktop/pgrwl/pgrwl/internal --include="*.go" --exclude="*_test.go" \
  | grep -E "\.(Info|Warn|Error|Debug)\(" | head -100

grep -rnE "\.(Info|Warn|Error|Debug)\(" /home/os/Desktop/pgrwl/pgrwl/internal \
  --include="*.go" --exclude="*_test.go" \
  | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1        /' \
  | head -100

grep -rn "\.Info(\|\.Warn(\|\.Error(\|\.Debug(" /home/os/Desktop/pgrwl/pgrwl/internal --include="*.go" --exclude="*_test.go" \
  | sed 's/.*\.\(Info\|Warn\|Error\|Debug\)("\([^"]*\)".*/\2/' | sort | uniq

# .InfoContext(...)
grep -rn "Context(" /home/os/Desktop/pgrwl/pgrwl/internal --include="*.go" --exclude="*_test.go" \
  | grep -E "\.(Info|Warn|Error|Debug)Context\("


