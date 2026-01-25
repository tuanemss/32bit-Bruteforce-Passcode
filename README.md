# 32-bit iOS Passcode Bruteforce (Ramdisk Method)

A professional ramdisk-based solution for bruteforcing 4-digit passcodes on all **32-bit iOS devices**. This project leverages a custom ramdisk to bypass system restrictions and execute a brute-force attack directly on the device.

---

## Introduction

I did this based on the source code of iphone-dataprotection, legacy-ios-kit, 32bit ramdisk by moewcat

You can easily find the source code here [iphone-dataprotection](https://github.com/dinosec/iphone-dataprotection)

You'll need to compile it to get the necessary tools, and it also contains important kernel patches that I mention below

---

## Kernel Patcher 
script [here](https://github.com/tuanemss/32bit-Bruteforce-Passcode/blob/main/resources/kernel_patch.py)

| Version | Key Patch (Pattern -> Replacement) | Description |
| :--- | :--- | :--- |
| **ARMv6** | `5D D0 36 4B 9A 42` -> `00 20 36 4B 9A 42` | IOAESAccelerator Enable UID |
| **iOS 4** | `56 D0 40 F6` -> `00 00 40 F6` | IOAESAccelerator Enable UID |
| **iOS 5** | `67 D0 40 F6` -> `00 20 40 F6` | IOAESAccelerator Enable UID |
| **iOS 6** | `B0 F5 FA 6F 00 F0 92 80` -> `B0 F5 FA 6F 0C 46 0C 46` | IOAESAccelerator Enable UID |
| **iOS 7** | `B0 F5 FA 6F 00 F0 A2 80` -> `B0 F5 FA 6F 0C 46 0C 46` | IOAESAccelerator Enable UID |
| **iOS 8/9**| `B0 F5 FA 6F 00 F0 82 80` -> `B0 F5 FA 6F 0C 46 0C 46` | IOAESAccelerator Enable UID |

---

## Supported Devices

This tool currently supports **all 32-bit iOS devices** 

---

## Usage Instructions

```bash
cd /path/bruteforce

# Start the bruteforce process
./bruteforce.sh
