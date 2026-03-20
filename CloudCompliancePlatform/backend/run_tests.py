import subprocess

def main():
    with open('test_output.txt', 'w') as f:
        subprocess.run(
            ['pytest', 'tests/unit/test_models.py', 'tests/unit/test_database.py', '-v', '--tb=short'],
            stdout=f,
            stderr=subprocess.STDOUT
        )

if __name__ == "__main__":
    main()
