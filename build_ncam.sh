#!/bin/bash
#
# Copyright (c) 2017 Javier Sayago <admin@lonasdigital.com>
# Contact: javilonas@esp-desarrolladores.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

version=0.2

while :
do

  clear

echo "============================================================"
echo " Build System NCam Version $version by Javier Sayago (Javilonas). "
echo "============================================================"
echo 
echo "> MAIN MENU"
echo
echo "  1 - Build ALL. (Including versions smargo)"
echo "  2 - Build x86 (Linux PC 32 bit - i686)."
echo "  3 - Build x86_64 (Linux PC 64-bits)."
echo "  4 - Build mips (Gigablue, Dream, Vu+, Xtrend, Formuler...)."
echo "  5 - Build mips-uclibc (Tiviar Plus and similar)."
echo "  6 - Build sh4 (Golden Media, Galaxy Innovations, Amiko...)."
echo "  7 - Build ppc (Power PC - DM600, 7000, 7020, 7020si...)."
echo "  8 - Build ppc-old (Power PC OLD - DM500, 500S, DBox2...)."
echo "  9 - Build cortexa9hf-vfp-neon (Cortex-A9 - Wetek, Vu+4k and similar)."
echo " 10 - Build router-openwrt-brcm47xx.mips (Routers openwrt brcm47xx)."
echo " 11 - Build router-openwrt-ar71xx.mips (Routers openwrt ar71xx)."
echo " 12 - Build router-openwrt-brcm63xx.mips (Routers openwrt brcm63xx)."
echo " 13 - Build arm-raspbian (Rasp, Prismcube and similar)."
echo " 14 - Build arm-marvell (Synology DS114, DS214 and similar)."
echo " 15 - Build arm-android (For Android ARM)."
echo " 16 - Build arm-mca (For Matrix CAM Air)."
echo
echo "  a - Advanced Options."
echo "  i - About Build System NCam."
echo "  x - Exit"
echo 
echo "- Enter option:"
  read opt


  if [ "$?" != "1" ]
  then
    case $opt in
      1) build_dir/build_all.sh;;
      2) build_dir/build_x86.sh;;
      3) build_dir/build_x86_64.sh;;
      4) build_dir/build_mips.sh;;
      5) build_dir/build_mips-uclibc.sh;;
      6) build_dir/build_sh4.sh;;
      7) build_dir/build_ppc.sh;;
      8) build_dir/build_ppc-old.sh;;
      9) build_dir/build_cortexa9hf-vfp-neon.sh;;
      10) build_dir/build_mips-router-openwrt-brcm47xx.sh;;
      11) build_dir/build_mips-router-openwrt-ar71xx.sh;;
      12) build_dir/build_mips-router-openwrt-brcm63xx.sh;;
      13) build_dir/build_arm-raspbian.sh;;
      14) build_dir/build_arm-marvell.sh;;
      15) build_dir/build_arm-android.sh;;
      16) build_dir/build_arm-mca.sh;;
      a) build_dir/advanced.sh $version; continue;;
      i) build_dir/info.sh $version; continue;;
      x) clear; echo; echo "Goodbye ;)"; echo; exit 1;;
      *) echo "Invalid option"; continue;;
    esac
  fi

done
