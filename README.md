# Electrode

This is an implementation of accelerating multi-Paxos Protocol using eBPF, as described in the paper ["Electrode: Accelerating Distributed
Protocols with eBPF"](https://www.usenix.org/system/files/nsdi23-zhou.pdf) from NSDI 2023.


## Contents

This repository mainly contains two parts:

1. Implementation of VR(Viewstamped Replication) protocol in `vr/`, the code is from [Speculative Paxos](https://github.com/UWSysLab/specpaxos). We did some modifications to implement our functions.
2. Implementation of the three optimizations in eBPF, you can find the code in `xdp-handler/`. The structure is from the source code of [BMC](https://github.com/Orange-OpenSource/bmc-cache).

## Building and Running

We did our experiment in [Cloudlab](https://cloudlab.us/) by using the `raw-pc` type machine `xl170`. The initial Disk Image is `UBUNTU20-64-STD`. 

Because we are using kernel version `5.8.0`, we should update this manually:

      wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
      sudo bash ubuntu-mainline-kernel.sh -i 5.8.0
      sudo reboot

You can check your kernel version by `uname -r`, before rebooting, the result is `5.4.0-100-generic`. After rebooting, the result is `5.8.0-050800-generic`.

Then install dependencies.
      
      sudo apt update
      sudo apt install llvm clang gpg curl tar xz-utils make gcc flex bison libssl-dev libelf-dev protobuf-compiler pkg-config libunwind-dev libssl-dev libprotobuf-dev libevent-dev libgtest-dev

Then we should build `xdp` modules, here we should run the script `kernel-src-download.sh` and `kernel-src-prepare.sh`, from [BMC project](https://www.usenix.org/conference/nsdi21/presentation/ghigoff). We did some modifications to support `5.8.0`.

      bash kernel-src-download.sh
      bash kernel-src-prepare.sh

Then you should be able to compile the code:

1. In `./xdp-handler/`, run `make clean` and `make`.
2. In `./`, run `make clean` and `make PARANOID=0`.

In our experiment, we disabled the adaptive batching in NIC and the irqbalance:

      sudo ifconfig ens1f1np1 mtu 3000 up
      sudo ethtool -C ens1f1np1 adaptive-rx off adaptive-tx off rx-frames 1 rx-usecs 0  tx-frames 1 tx-usecs 0
      sudo ethtool -C ens1f1np1 adaptive-rx off adaptive-tx off rx-frames 1 rx-usecs 0  tx-frames 1 tx-usecs 0
      sudo ethtool -L ens1f1np1 combined 1
      sudo service irqbalance stop
      (let CPU=0; cd /sys/class/net/ens1f1np1/device/msi_irqs/;
         for IRQ in *; do
            echo $CPU | sudo tee /proc/irq/$IRQ/smp_affinity_list
         done)

Then you need to create a config file like (example in `./config.txt`)

      f <number of failures tolerated>
      replica <hostname>:<port>
      replica <hostname>:<port>
      ...

Because in `TC_BROADCAST` optimization, we need to assign the mac address of the destination server, you should write the MACADDR of the cluster in line 281 of `xdp-handler/fast_user.c`. Also you need to modify the line 17 of `xdp-handler/fast_common.h`, the `CLUSTER_SIZE` should equals to $2f + 1$.

Then you are able to run the code. Because our optimizations are kind of independent, which means you can specify which optimization to add, we control this by defining variables when building the project. Three optimizations are: `TC_BROADCAST`, `FAST_QUORUM_PRUNE`, and `FAST_REPLY`.

Recompile the eBPF code, in `xdp-handler/`:

      make clean && make EXTRA_CFLAGS="-DTC_BROADCAST -DFAST_QUORUM_PRUNE -DFAST_REPLY"

Recompile the Replica code:

      make clean && make CXXFLAGS="-DTC_BROADCAST -DFAST_QUORUM_PRUNE -DFAST_REPLY"

Run the eBPF code, in `xdp-handler/`:

      sudo ./fast ens1f1np1

Run the Replica-idx (eg, 0, 1, and 2 when `f`=1) on different replica machines:

      sudo taskset -c 1 ./bench/replica -c config.txt -m vr -i {idx}

Then run the client on a separate client machine, n is the number of requests(you can also specify warmup by `-w` and # of clients by `-t`):

      ./bench/client -c config.txt -m vr -n 10000

In the end of the client run, you can get the elapsed time (which can be used to calculate throughput) and latency. 

**NOTICE:** our code currently doesn't handle non-critical path cases like packet loss/reorder (which we do not observe in Cloudlab machines), machine failure, and network failure.

## Cite this work
BibTex:

      @inproceedings{zhou2023electrode,
        title={{Electrode: Accelerating Distributed Protocols with eBPF}},
        author={Zhou, Yang and Wang, Zezhou and Dharanipragada, Sowmya and Yu, Minlan},
        booktitle={20th USENIX Symposium on Networked Systems Design and Implementation (NSDI 23)},
        pages={1391--1407},
        year={2023}
      }
