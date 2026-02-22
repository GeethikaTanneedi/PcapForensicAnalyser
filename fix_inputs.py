# fix_inputs_unicode.py
import os

files = ['step2_reader.py', 'step3_port_scan.py', 'step4_bruteforce.py', 'step5_credentials.py']

for file in files:
    try:
        # Read with utf-8 encoding to handle emojis
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace input lines
        if 'input("Press Enter to exit...")' in content:
            new_content = content.replace(
                'input("Press Enter to exit...")',
                'import sys\n    if sys.stdin.isatty():\n        input("Press Enter to exit...")'
            )
            
            # Write back with utf-8 encoding
            with open(file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"✅ Fixed {file}")
        else:
            print(f"⏭️  No input line in {file}")
            
    except FileNotFoundError:
        print(f"❌ {file} not found")
    except Exception as e:
        print(f"❌ Error in {file}: {e}")

print("\n🎉 Done! Now commit and push:")
