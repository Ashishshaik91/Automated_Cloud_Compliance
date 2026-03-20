import subprocess

def main():
    with open('/tmp/test_output.txt', 'w') as f:
        subprocess.run(
            ['pytest', 'tests/', '--cov=app', '--cov-fail-under=80', '--cov-report=term-missing'],
            stdout=f,
            stderr=subprocess.STDOUT
        )

if __name__ == "__main__":
    main()
