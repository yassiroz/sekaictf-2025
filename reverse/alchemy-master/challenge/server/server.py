from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import sys


launch_exe = Path(__file__).parent / 'launch.exe'


def main() -> None:
    if not launch_exe.exists():
        print('something is wrong! contact admins')
        return

    print('hi! please enter your cpp code line by line, then it end with a __END__ line')

    lines = []
    while True:
        l = input()
        if l == '__END__':
            break
        lines.append(l)

    code = '\n'.join(lines)

    print('gotcha, lets compile this!')
    with TemporaryDirectory() as tmpdir:
        cwd = str(Path(tmpdir).absolute())
        file_path = Path(tmpdir) / 'solution.cpp'
        file_path.write_text(code)

        completed = subprocess.run(
            [str(launch_exe.resolve()), str(file_path.resolve())],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd,
        )

        sys.stdout.write('=== cl.exe ===\n')
        sys.stdout.write(completed.stdout.replace(cwd + '\\', ''))
        sys.stdout.flush()


if __name__ == '__main__':
    main()
