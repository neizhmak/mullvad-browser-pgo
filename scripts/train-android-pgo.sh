#!/usr/bin/env bash
# Automated Android AArch64 PGO Training Script using ReDroid container on ARM64
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workload_file="$SCRIPT_DIR/android-pgo-workload.html"
runner_py="$SCRIPT_DIR/train-runner.py"

apk_path="$(realpath "${1:-/tmp/instrumented.apk}")"
output_dir="$(realpath -m "${2:-/tmp/android-pgo-output}")"

echo "=========================================================="
echo "Starting Android AArch64 PGO Training Pipeline"
echo "SCRIPT_DIR: $SCRIPT_DIR"
echo "Workload:   $workload_file"
echo "APK Path:   $apk_path"
echo "Output Dir: $output_dir"
echo "=========================================================="

mkdir -p "$output_dir"
mkdir -p /tmp/pgo_raw

# 1. Setup DKMS binder if not already present
if [[ ! -c /dev/binder ]]; then
  echo "Setting up binder_linux kernel module and host tools..."
  sudo apt-get update
  sudo apt-get install -y git dkms linux-headers-$(uname -r) build-essential adb curl python3-pip
  sudo apt-get install -y llvm-19 llvm-19-tools || true
  pip3 install --break-system-packages marionette-driver || true
  cd /tmp
  if [[ ! -d anbox-modules ]]; then
    git clone https://github.com/choff/anbox-modules.git
  fi
  cd anbox-modules/binder
  make -j$(nproc)
  sudo insmod binder_linux.ko devices="binder,hwbinder,vndbinder" || true
  
  sudo mkdir -p /dev/binderfs || true
  sudo mount -t binder binder /dev/binderfs || true
  
  for dev in binder hwbinder vndbinder; do
    if [[ -e /dev/binderfs/$dev && ! -e /dev/$dev ]]; then
      sudo ln -s /dev/binderfs/$dev /dev/$dev
    fi
    if [[ -e /dev/$dev ]]; then
      sudo chmod 666 /dev/$dev
    fi
    if [[ -e /dev/binderfs/$dev ]]; then
      sudo chmod 666 /dev/binderfs/$dev
    fi
  done
else
  sudo apt-get update
  sudo apt-get install -y adb curl python3-pip || true
  sudo apt-get install -y llvm-19 llvm-19-tools || true
  pip3 install --break-system-packages marionette-driver || true
fi

ls -la /dev/binder*

# 2. Launch ReDroid container
if ! docker ps | grep -q redroid; then
  echo "Starting ReDroid Android 12 ARM64 container..."
  docker run -d --rm --privileged     --name redroid     -p 5555:5555     -v /tmp/redroid-data:/data     redroid/redroid:12.0.0-latest     androidboot.redroid_width=1080     androidboot.redroid_height=1920     androidboot.redroid_dpi=480     androidboot.redroid_gpu_mode=guest
  sleep 10
fi

# 3. Connect ADB, switch to root, and wait for boot
echo "Connecting to ADB..."
adb connect 127.0.0.1:5555 || true
target_dev=$(adb devices | grep -E "5555|device$" | head -n 1 | awk '{print $1}')
echo "Target device: $target_dev"

echo "Enabling ADB root and disabling SELinux..."
adb -s "$target_dev" root || true
sleep 3
adb connect 127.0.0.1:5555 || true
target_dev=$(adb devices | grep -E "5555|device$" | head -n 1 | awk '{print $1}')
adb -s "$target_dev" shell setenforce 0 || true

echo "Waiting for Android to boot..."
for i in $(seq 1 60); do
  boot_status=$(adb -s "$target_dev" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)
  if [[ "$boot_status" == "1" ]]; then
    echo "Android booted in check $i."
    break
  fi
  sleep 2
done

# 4. Install instrumented APK
echo "Installing instrumented APK: $apk_path..."
adb -s "$target_dev" install -r "$apk_path"

pkg_name=$(adb -s "$target_dev" shell pm list packages | grep -E "mullvad|firefox|fenix" | head -n 1 | cut -d: -f2 | tr -d '\r')
echo "Installed package: $pkg_name"

# Grant all permissions to the app
adb -s "$target_dev" shell pm grant "$pkg_name" android.permission.WRITE_EXTERNAL_STORAGE 2>/dev/null || true
adb -s "$target_dev" shell pm grant "$pkg_name" android.permission.READ_EXTERNAL_STORAGE 2>/dev/null || true

# 5. Push training workload
echo "Pushing training workload: $workload_file..."
adb -s "$target_dev" shell "mkdir -p /data/local/tmp/workload && chmod 777 /data/local/tmp/workload"
adb -s "$target_dev" push "$workload_file" /data/local/tmp/workload/index.html
adb -s "$target_dev" shell "chmod 666 /data/local/tmp/workload/index.html"

# 6. Configure environment and GeckoView debug config
echo "Configuring LLVM profiling environment..."
adb -s "$target_dev" shell "rm -rf /data/local/tmp/pgo_profile && mkdir -p /data/local/tmp/pgo_profile && chmod 777 /data/local/tmp /data/local/tmp/pgo_profile"
adb -s "$target_dev" shell "mkdir -p /sdcard/pgo_profile && chmod 777 /sdcard/pgo_profile"

# Push official GeckoView config YAML for automation
cat << EOF > /tmp/geckoview-config.yaml
env:
  LLVM_PROFILE_FILE: "/data/local/tmp/pgo_profile/default_%p_%m.profraw"
  MOZ_JAR_LOG_FILE: "/data/local/tmp/pgo_profile/en-US.log"
  MOZ_IN_AUTOMATION: "1"
  XPCOM_DEBUG_BREAK: "warn"
args:
  - "--marionette"
prefs:
  marionette.defaultPrefs.enabled: true
  marionette.port: 2828
EOF
adb -s "$target_dev" push /tmp/geckoview-config.yaml "/data/local/tmp/${pkg_name}-geckoview-config.yaml"
adb -s "$target_dev" shell "chmod 666 /data/local/tmp/${pkg_name}-geckoview-config.yaml"
adb -s "$target_dev" shell am set-debug-app --persistent "$pkg_name"

cat << 'EOF' > /tmp/android_pgo_wrap.sh
#!/system/bin/sh
export LLVM_PROFILE_FILE="/data/local/tmp/pgo_profile/default_%p_%m.profraw"
export MOZ_JAR_LOG_FILE="/data/local/tmp/pgo_profile/en-US.log"
export MOZ_IN_AUTOMATION=1
export XPCOM_DEBUG_BREAK=warn
exec "$@"
EOF
chmod 755 /tmp/android_pgo_wrap.sh
adb -s "$target_dev" push /tmp/android_pgo_wrap.sh /data/local/tmp/wrap.sh
adb -s "$target_dev" shell chmod 755 /data/local/tmp/wrap.sh
adb -s "$target_dev" shell setprop wrap."$pkg_name" /data/local/tmp/wrap.sh

# Forward Marionette port
adb -s "$target_dev" forward tcp:2828 tcp:2828 || true

# 7. Start browser with training workload and explicit GeckoView env extras
echo "Launching browser with training workload..."
adb -s "$target_dev" shell am start -n "$pkg_name/org.mozilla.fenix.HomeActivity"   -a android.intent.action.VIEW   -d "file:///data/local/tmp/workload/index.html"   --es env0 "LLVM_PROFILE_FILE=/data/local/tmp/pgo_profile/default_%p_%m.profraw"   --es env1 "MOZ_JAR_LOG_FILE=/data/local/tmp/pgo_profile/en-US.log"   --es env2 "MOZ_IN_AUTOMATION=1"   --es env3 "XPCOM_DEBUG_BREAK=warn"

# 8. Run automated training session
echo "Attempting Marionette navigation..."
python3 -u "$runner_py" || true

echo "Running interactive workload loop for 120 seconds..."
for t in $(seq 1 12); do
  echo "Training in progress ($((t * 10))s / 120s)..."
  sleep 10
  adb -s "$target_dev" shell input swipe 500 1200 500 400 300 || true
  adb -s "$target_dev" shell input tap 540 960 || true
done

# Take screenshot to verify training execution
adb -s "$target_dev" shell screencap -p /data/local/tmp/training_screen.png || true
adb -s "$target_dev" pull /data/local/tmp/training_screen.png "$output_dir/training_screen.png" || true

# Send clean Back keyevents to let Activities, tabs, and child content processes shut down naturally
echo "Sending Back keyevents to close tabs and flush child profile buffers..."
for k in 1 2 3 4 5; do
  adb -s "$target_dev" shell input keyevent 4 || true
  sleep 2
done

# Wait for Gecko to complete profile buffer flushing
echo "Waiting for Gecko profile buffer flush..."
sleep 15

pids=$(adb -s "$target_dev" shell pidof "$pkg_name" || true)
if [[ -n "$pids" ]]; then
  echo "Closing remaining browser processes: $pids..."
  for pid in $pids; do
    adb -s "$target_dev" shell "kill -15 $pid" 2>/dev/null || true
  done
  sleep 5
  adb -s "$target_dev" shell am force-stop "$pkg_name" || true
fi

# 9. Scan for profile files across the system
echo "Searching and collecting .profraw files..."
adb -s "$target_dev" shell "cp -r /data/data/$pkg_name/*.profraw /data/local/tmp/pgo_profile/ 2>/dev/null || true"
adb -s "$target_dev" shell "cp -r /data/user/0/$pkg_name/*.profraw /data/local/tmp/pgo_profile/ 2>/dev/null || true"
adb -s "$target_dev" shell "cp -r /sdcard/pgo_profile/*.profraw /data/local/tmp/pgo_profile/ 2>/dev/null || true"

adb -s "$target_dev" pull /data/local/tmp/pgo_profile/ /tmp/pgo_raw/ || true

# Find all profraw files pulled
mkdir -p "$output_dir"
raw_files=( $(find /tmp/pgo_raw/ -type f -name "*.profraw") )
profraw_count="${#raw_files[@]}"
echo "Found $profraw_count raw profile files in /tmp/pgo_raw/."

# Detect llvm-profdata binary supporting format version 10 (LLVM 19+)
LLVM_PROFDATA=""
for cand in llvm-profdata-21 llvm-profdata-20 llvm-profdata-19 /usr/lib/llvm-19/bin/llvm-profdata /usr/lib/llvm-20/bin/llvm-profdata llvm-profdata; do
  if command -v "$cand" >/dev/null 2>&1; then
    ver=$("$cand" --version 2>&1 || true)
    if [[ "$ver" != *"version 18."* && "$ver" != *"version 17."* ]]; then
      LLVM_PROFDATA=$(command -v "$cand")
      break
    fi
  fi
done

if [[ -z "$LLVM_PROFDATA" ]]; then
  echo "Modern llvm-profdata not found, installing llvm-19 from package manager..."
  sudo apt-get update || true
  sudo apt-get install -y llvm-19 llvm-19-tools || true
  for cand in llvm-profdata-19 /usr/lib/llvm-19/bin/llvm-profdata llvm-profdata; do
    if command -v "$cand" >/dev/null 2>&1; then
      LLVM_PROFDATA=$(command -v "$cand")
      break
    fi
  done
fi

if [[ -z "$LLVM_PROFDATA" ]] || [[ "$("$LLVM_PROFDATA" --version 2>&1)" == *"version 18."* ]]; then
  echo "Attempting to install LLVM 19 from apt.llvm.org..."
  curl -s https://apt.llvm.org/llvm.sh | sudo bash -s 19 || true
  if command -v llvm-profdata-19 >/dev/null 2>&1; then
    LLVM_PROFDATA=$(command -v llvm-profdata-19)
  fi
fi

echo "Using LLVM_PROFDATA: $LLVM_PROFDATA ($("$LLVM_PROFDATA" --version 2>&1 | head -n 1))"

if [[ "$profraw_count" -gt 0 ]]; then
  echo "Merging raw profiles into android-aarch64-pgo.profdata using $LLVM_PROFDATA..."
  "$LLVM_PROFDATA" merge -output="$output_dir/android-aarch64-pgo.profdata" "${raw_files[@]}"
  
  jarlog_cand=$(find /tmp/pgo_raw/ -type f -name "en-US.log" | head -n 1)
  if [[ -n "$jarlog_cand" && -f "$jarlog_cand" ]]; then
    cp "$jarlog_cand" "$output_dir/en-US.log"
  fi
  
  echo "Validating merged profile..."
  "$LLVM_PROFDATA" show --counts "$output_dir/android-aarch64-pgo.profdata" | head -n 25
  echo "SUCCESS: Merged profile generated at $output_dir/android-aarch64-pgo.profdata"
else
  echo "Searching entire Android filesystem for *.profraw..."
  all_profraws=$(adb -s "$target_dev" shell "find /data -name '*.profraw' 2>/dev/null" || true)
  echo "Found files on device: $all_profraws"
  for f in $all_profraws; do
    echo "Pulling $f..."
    adb -s "$target_dev" pull "$f" /tmp/pgo_raw/ || true
  done
  raw_files=( $(find /tmp/pgo_raw/ -type f -name "*.profraw") )
  if [[ "${#raw_files[@]}" -gt 0 ]]; then
    echo "Merging discovered raw profiles..."
    "$LLVM_PROFDATA" merge -output="$output_dir/android-aarch64-pgo.profdata" "${raw_files[@]}"
    "$LLVM_PROFDATA" show --counts "$output_dir/android-aarch64-pgo.profdata" | head -n 25
    echo "SUCCESS: Merged profile generated at $output_dir/android-aarch64-pgo.profdata"
  else
    echo "Error: No .profraw profiles were generated during the run." >&2
    exit 1
  fi
fi

echo "PGO Training completed successfully."
