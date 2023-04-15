import os
import sys
import json
import subprocess

def run(file_path):
    try:
        # Change the path to the local eslint executable in your project
        eslint_path = os.path.join(os.getcwd(), "node_modules", ".bin", "eslint")
        result = subprocess.run(
            [eslint_path, "--format", "json", file_path],
            capture_output=True,
            text=True,
        )
        if result.returncode not in [0, 1]:
            result.check_returncode()
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running ESLint: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error running ESLint: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python eslint_runner.py [filepath]")
        sys.exit(1)

    file_path = sys.argv[1]
    print(run(file_path))
