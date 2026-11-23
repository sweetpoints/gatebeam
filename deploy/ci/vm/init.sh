#!/bin/sh
# PID1 inside the disposable guest only; no commands here run on the Runner.
export COMPOSE_ANSI=never COMPOSE_PROGRESS=plain NO_COLOR=1
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run /tmp /sys/fs/cgroup
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t cgroup2 none /sys/fs/cgroup
# Standard guest entropy device; host access is only ordinary /dev/urandom reads.
modprobe virtio_rng
ip link set lo up
iface=$(ls /sys/class/net | grep -v '^lo$' | head -n 1)
ip link set "$iface" up
ip addr add 10.0.2.15/24 dev "$iface"
ip route add default via 10.0.2.2
printf 'nameserver 10.0.2.3\n' > /etc/resolv.conf
finish() { printf '\nGATEBEAM_VM_EXIT=%s\n' "$1"; sync; /bin/busybox poweroff -f; }
trap 'finish 1' EXIT
# Reuse the existing CI image mirror inside this disposable guest. Keep its
# address outside guest Docker subnets so traffic reaches the Runner network.
dockerd --host unix:///var/run/docker.sock --storage-driver overlay2 --exec-opt native.cgroupdriver=cgroupfs --registry-mirror http://172.17.0.1:5005 --bip 172.30.0.1/16 --default-address-pool base=10.240.0.0/16,size=24 > /tmp/dockerd.log 2>&1 &
ready=false
for i in $(seq 1 90); do if docker info > /tmp/docker-info 2>&1; then ready=true; break; fi; sleep 1; done
if [ "$ready" != true ]; then cat /tmp/docker-info /tmp/dockerd.log; exit 1; fi
set -eu
/gatebeam-run
trap - EXIT
finish 0
