import os
import signal
import subprocess
from socket import SOL_SOCKET, SO_REUSEADDR


def kill_process_by_port(port):
    
    try:
        result = subprocess.run(
            ['netstat', '-ano', '|', 'findstr', str(port)],
            shell=True,
            capture_output=True,
            text=True
        )

        if not result.stdout:
            print(f"端口 {port} 未被占用")
            return True

        print(result.stdout)

        lines = result.stdout.strip().split('\n')
        pids = set()

        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                pids.add(parts[-1])

        if not pids:
            return False

        for pid in pids:
            try:
                subprocess.run(['taskkill', '/F', '/PID', pid], check=True)
            except subprocess.CalledProcessError as e:
                continue

        return True

    except Exception as e:
        return False


def release_port(port):
    if kill_process_by_port(port):
        return True
    else:
        return False


if __name__ == "__main__":
    PORT_TO_RELEASE = 12345
    release_port(PORT_TO_RELEASE)
