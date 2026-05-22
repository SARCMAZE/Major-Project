import os
import subprocess
import sys
import time


def run_l1():
    print("\nRunning L1 Layer with relaxed default thresholds...")
    # write a predictable L1 output filename so downstream consumers can be explicit
    l1_out = os.path.join(os.getcwd(), "l1_runtime_output.jsonl")
    subprocess.run([sys.executable, "L1.balanced.py", "--min-score", "8", "--output", l1_out], check=True)
    return l1_out


def run_l2():
    print("\nRunning L2 Layer with progress reporting...")
    # This function is intentionally a no-op; main runs L2 with explicit args
    return None


def start_api_server():
    print("\nStarting local API server...")
    return subprocess.Popen([sys.executable, "api_server.py"], cwd=os.getcwd())


def start_frontend():
    print("\nStarting local React frontend...")
    npm_command = "npm.cmd" if os.name == "nt" else "npm"
    try:
        return subprocess.Popen(
            [npm_command, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"],
            cwd=os.path.join(os.getcwd(), "frontend"),
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            "npm is not installed or not available in PATH. Install Node.js and run `npm install` in the frontend/ folder."
        ) from error


if __name__ == "__main__":
    api_process = None
    frontend_process = None
    try:
        # Run L1 and capture the explicit output filename
        l1_out = run_l1()

        # run L2 explicitly using the L1 output
        l2_out = os.path.join(os.getcwd(), "l2_output1-6PP.JSONL")
        subprocess.run([
            sys.executable,
            "L2_processor.py",
            "--input",
            l1_out,
            "--output",
            l2_out,
            "--model",
            "llama3.2:3b",
            "--sample-size",
            "20000",
            "--min-severity",
            "MEDIUM",
            "--target-alerts",
            "30",
            "--verbose",
        ], check=True)

        l3_out = os.path.join(os.getcwd(), "l3_output_review.jsonl")
        subprocess.run([
            "/usr/local/bin/python3",
            "L3_processor.py",
            "--input",
            l2_out,
            "--output",
            l3_out,
            "--window-size",
            "8",
            "--epochs",
            "8",
            "--verbose",
        ], check=True)

        api_process = start_api_server()
        frontend_process = start_frontend()

        print("\nPipeline complete. Open the dashboard at http://127.0.0.1:5173")
        print("Press Ctrl+C to stop the API server and frontend.")

        while True:
            if api_process.poll() is not None:
                print("API server stopped.")
                break
            if frontend_process.poll() is not None:
                print("Frontend process stopped.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping pipeline...")
    except Exception as error:
        print("Pipeline failed:", error)
    finally:
        for proc in (api_process, frontend_process):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
