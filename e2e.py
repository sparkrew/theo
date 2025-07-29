import subprocess
import psutil
import time

GRAPHOPPER_CMD = [
    "mvn",
    "org.codehaus.mojo:exec-maven-plugin:3.5.1:exec",
    "-Dexec.executable=java",
    '-Dexec.args=' +
    '-Ddw.graphhopper.datareader.file=/Users/yogyagamage/Documents/UdeM/theo/berlin-latest.osm.pbf '
    '--add-opens=java.base/java.lang=ALL-UNNAMED '
    '--add-opens=java.base/java.util=ALL-UNNAMED '
    '-XX:StartFlightRecording=name=jfrTestRecording,settings=/Users/yogyagamage/Documents/UdeM/theo/settings.jfc,'
    'filename=/Users/yogyagamage/Documents/KTH/theo/prod/graphhopper-new/web/jfr-report1.jfr '
    '-javaagent:/Users/yogyagamage/Documents/UdeM/theo/theo-agent/target/theo-agent-1.0-SNAPSHOT-jar-with-dependencies.jar '
    '-classpath %classpath com.graphhopper.application.GraphHopperApplication server '
    '/Users/yogyagamage/Documents/KTH/theo/prod/graphhopper-new/config-example.yml'
]

BASE_URL = "http://localhost:8989"

def wait_for_server_output(process, target_line, timeout=120):
    start_time = time.time()
    for line in iter(process.stdout.readline, ''):
        decoded_line = line.strip()
        print(decoded_line)  # Optional: print live logs
        if target_line in decoded_line:
            print("Detected server startup line.")
            return True
        if time.time() - start_time > timeout:
            break
    raise TimeoutError("Server did not output startup confirmation in time.")

def kill_process_tree(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            print(f"Killing child PID {child.pid}")
            child.kill()
        print(f"Killing parent PID {pid}")
        parent.kill()
    except psutil.NoSuchProcess:
        print("Process already terminated.")


def wait_then_shutdown(process):
    time.sleep(30)  # Let the server run and collect JFR data

    parent = psutil.Process(process.pid)
    children = parent.children(recursive=True)

    # Stop JFR on Java child (if any)
    for child in children:
        if "java" in child.name().lower():
            print(f"Stopping JFR for Java PID {child.pid}")
            try:
                subprocess.run(["jcmd", str(child.pid), "JFR.stop", "name=jfrTestRecording"], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Failed to stop JFR: {e}")

    # Kill all children first
    for child in children:
        try:
            print(f"Killing child process PID {child.pid}")
            child.terminate()
        except psutil.NoSuchProcess:
            pass

    gone, alive = psutil.wait_procs(children, timeout=5)
    for child in alive:
        print(f"Force killing child PID {child.pid}")
        child.kill()

    # Finally kill the parent
    try:
        print(f"Killing parent process PID {parent.pid}")
        parent.terminate()
        parent.wait(timeout=5)
    except (psutil.NoSuchProcess, psutil.TimeoutExpired):
        parent.kill()

def test_graphhopper_route():
    process = subprocess.Popen(
        GRAPHOPPER_CMD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=True
    )
    try:
        wait_for_server_output(process, "[main] INFO  org.eclipse.jetty.server.Server - Started", timeout=120)
        wait_then_shutdown(process)
    except Exception as e:
        print(str(e))
        kill_process_tree(process.pid)

if __name__ == "__main__":
    test_graphhopper_route()