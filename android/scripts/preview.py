"""Capture the actual APK and exercise profile switching on an empty emulator.
All displayed NAS metadata is explicitly marked as demo; no real credentials.
"""
import json
import pathlib
import re
import subprocess
import time
import xml.etree.ElementTree as ET

package = "io.github.viperboss.nknguard.debug"
output = pathlib.Path("android-preview")
output.mkdir(exist_ok=True)

def adb(*args, **kwargs):
    return subprocess.run(["adb", *args], check=True, **kwargs)

def start():
    adb("shell", "am", "start", "-n", package + "/io.github.viperboss.nknguard.ui.MainActivity")
    time.sleep(5)

def screenshot(name):
    with (output / name).open("wb") as file:
        adb("exec-out", "screencap", "-p", stdout=file)

adb("install", "-r", "android/app/build/outputs/apk/debug/app-debug.apk")
start()
adb("shell", "am", "force-stop", package)
office = "7a1293e2-003b-4cfa-82aa-ae5e9603c3cc"
fixture = {"selected": "legacy", "entries": [
    {"id": "legacy", "name": "家庭 NAS · 演示", "nas_id": "demo-home", "address": "", "virtual_ip": "10.88.10.1"},
    {"id": office, "name": "办公室 NAS · 演示", "nas_id": "demo-office", "address": "", "virtual_ip": "10.88.20.1"},
]}
adb("shell", f"run-as {package} sh -c 'cat > files/nas-registry.json'", input=json.dumps(fixture, ensure_ascii=False).encode())
start()
screenshot("android-home.png")
adb("shell", "uiautomator", "dump", "/sdcard/nkg-preview.xml")
xml = subprocess.check_output(["adb", "shell", "cat", "/sdcard/nkg-preview.xml"])
nodes = ET.fromstring(xml).iter("node")
target = next(node for node in nodes if node.get("text") == "办公室 NAS · 演示")
x1, y1, x2, y2 = map(int, re.findall(r"\d+", target.get("bounds")))
adb("shell", "input", "tap", str((x1+x2)//2), str((y1+y2)//2))
time.sleep(5)
current = json.loads(subprocess.check_output(["adb", "shell", "run-as", package, "cat", "files/nas-registry.json"]))
assert current["selected"] == office, "NAS card did not switch active profile"
assert len(current["entries"]) == 2, "Switch deleted another NAS"
adb("shell", "run-as", package, "ls", "files/secrets.bin", f"files/nas/{office}/secrets.bin")
screenshot("android-devices.png")
print("Native UI and isolated NAS profile switch passed")
