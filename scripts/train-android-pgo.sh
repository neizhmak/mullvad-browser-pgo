#!/usr/bin/env bash
# Automated Android AArch64 PGO Training Script using ReDroid container on ARM64
set -euo pipefail

apk_path="${1:-/tmp/instrumented.apk}"
output_dir="${2:-/tmp/android-pgo-output}"

echo "=========================================================="
echo "Starting Android AArch64 PGO Training Pipeline"
echo "APK Path: $apk_path"
echo "Output Dir: $output_dir"
echo "=========================================================="

mkdir -p "$output_dir"
mkdir -p /tmp/pgo_raw

# 1. Setup DKMS binder if not already present
if [[ ! -c /dev/binder ]]; then
  echo "Setting up binder_linux kernel module..."
  sudo apt-get update
  sudo apt-get install -y git dkms linux-headers-$(uname -r) build-essential adb curl llvm
  cd /tmp
  if [[ ! -d anbox-modules ]]; then
    git clone https://github.com/choff/anbox-modules.git
  fi
  cd anbox-modules/binder
  make -j$(nproc)
  sudo insmod binder_linux.ko devices="binder,hwbinder,vndbinder" || true
  
  mkdir -p /dev/binderfs || true
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
fi

ls -la /dev/binder*

# 2. Launch ReDroid container
if ! docker ps | grep -q redroid; then
  echo "Starting ReDroid Android 12 ARM64 container..."
  docker run -d --rm --privileged     --name redroid     -p 5555:5555     -v /tmp/redroid-data:/data     redroid/redroid:12.0.0-latest     androidboot.redroid_width=1080     androidboot.redroid_height=1920     androidboot.redroid_dpi=480     androidboot.redroid_gpu_mode=guest
  sleep 10
fi

# 3. Connect ADB and wait for boot
echo "Connecting to ADB..."
adb connect 127.0.0.1:5555 || true
target_dev=$(adb devices | grep -E "5555|device$" | head -n 1 | awk '{print $1}')
echo "Target device: $target_dev"

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
echo "Installing instrumented APK..."
adb -s "$target_dev" install -r "$apk_path"

pkg_name=$(adb -s "$target_dev" shell pm list packages | grep -E "mullvad|firefox|fenix" | head -n 1 | cut -d: -f2 | tr -d '\r')
echo "Installed package: $pkg_name"

# 5. Push training workload
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workload_file="$SCRIPT_DIR/android-pgo-workload.html"
echo "Pushing training workload: $workload_file..."
adb -s "$target_dev" shell "mkdir -p /data/local/tmp/workload"
adb -s "$target_dev" push "$workload_file" /data/local/tmp/workload/index.html

# 6. Configure environment and wrapper for LLVM profile writing
echo "Configuring LLVM profiling environment..."
adb -s "$target_dev" shell "rm -rf /data/local/tmp/pgo_profile && mkdir -p /data/local/tmp/pgo_profile && chmod -R 777 /data/local/tmp/pgo_profile"

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
echo "Wrapper configured for $pkg_name."

# 7. Start browser with training workload
echo "Launching browser with training workload..."
adb -s "$target_dev" shell am start -n "$pkg_name/org.mozilla.fenix.HomeActivity" -a android.intent.action.VIEW -d "file:///data/local/tmp/workload/index.html"

# 8. Let training workload run
echo "Running PGO training workload for 120 seconds..."
for t in $(seq 1 12); do
  echo "Training in progress ($((t * 10))s / 120s)..."
  sleep 10
  # Simulate user interaction: scrolling
  adb -s "$target_dev" shell input swipe 500 1200 500 400 300 || true
done

# Take screenshot to verify training execution
adb -s "$target_dev" shell screencap -p /data/local/tmp/training_screen.png || true
adb -s "$target_dev" pull /data/local/tmp/training_screen.png "$output_dir/training_screen.png" || true

# 9. Stop browser gracefully to flush profile counters
echo "Stopping browser to flush profile buffers..."
# Send Back keyevents to let Activities finish cleanly
for k in 1 2 3; do
  adb -s "$target_dev" shell input keyevent 4 || true
  sleep 1
done
pids=$(adb -s "$target_dev" shell pidof "$pkg_name" || true)
for pid in $pids; do
  adb -s "$target_dev" shell kill -15 "$pid" || true
done
sleep 8
adb -s "$target_dev" shell am force-stop "$pkg_name" || true
sleep 2

# 10. Pull raw profiles
echo "Pulling profile data..."
adb -s "$target_dev" pull /data/local/tmp/pgo_profile/ /tmp/pgo_raw/ || true

ls -la /tmp/pgo_raw/pgo_profile/ || true

# 11. Merge profiles with llvm-profdata
profraw_count=$(find /tmp/pgo_raw/pgo_profile/ -type f -name "*.profraw" | wc -l)
echo "Found $profraw_count raw profile files."

if [[ "$profraw_count" -gt 0 ]]; then
  echo "Merging raw profiles into android-aarch64-pgo.profdata..."
  llvm-profdata merge -output="$output_dir/android-aarch64-pgo.profdata" /tmp/pgo_raw/pgo_profile/*.profraw
  
  if [[ -f /tmp/pgo_raw/pgo_profile/en-US.log ]]; then
    cp /tmp/pgo_raw/pgo_profile/en-US.log "$output_dir/en-US.log"
  fi
  
  echo "Validating merged profile..."
  llvm-profdata show --counts "$output_dir/android-aarch64-pgo.profdata" | head -n 20
  echo "SUCCESS: Merged profile generated at $output_dir/android-aarch64-pgo.profdata"
else
  echo "WARNING: No .profraw files collected directly from wrapper; searching data dir..."
  adb -s "$target_dev" shell "find /data -name '*.profraw' 2>/dev/null" || true
fi

echo "PGO Training completed."
