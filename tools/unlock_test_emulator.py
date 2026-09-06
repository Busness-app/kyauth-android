"""Unlock the disposable CI emulator after configuring its fixture PIN."""
import subprocess
import time
import xml.etree.ElementTree as ET


def adb(*args):
    return subprocess.check_output(["adb", *args], text=True)


assert adb("shell", "getprop", "ro.kernel.qemu").strip() == "1", "Emulator required"
adb("shell", "input", "keyevent", "KEYCODE_SLEEP")
time.sleep(1)
adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
adb("shell", "input", "keyevent", "KEYCODE_MENU")
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    adb("shell", "input", "keyevent", "KEYCODE_MENU")
    try:
        adb("shell", "uiautomator", "dump", "/sdcard/ci-unlock.xml")
        root = ET.fromstring(adb("exec-out", "cat", "/sdcard/ci-unlock.xml"))
    except (ET.ParseError, subprocess.CalledProcessError):
        # SystemUI can return no accessibility root while the screen is waking.
        time.sleep(1)
        continue
    if any(node.get("resource-id") == "com.android.systemui:id/pinEntry"
           and node.get("focused") == "true" for node in root.iter("node")):
        break
    time.sleep(1)
else:
    raise RuntimeError("The emulator PIN screen did not become ready")
adb("shell", "input", "text", "246810")
adb("shell", "input", "keyevent", "KEYCODE_ENTER")
while time.monotonic() < deadline:
    if "showing=false" in adb("shell", "dumpsys", "window", "policy"):
        print("CI emulator unlocked")
        break
    time.sleep(1)
else:
    raise RuntimeError("The emulator did not dismiss its lock screen")
