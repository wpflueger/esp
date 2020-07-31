# Script

set board [lindex $argv 2]

set prjname "project_"
append prjname $board

open_project -reset $prjname

set topname [lindex $argv 3]

set_top $topname

set CFLAGS "-I../src -I../tb/tests"

add_files ../src/sha2.h -cflags $CFLAGS
add_files ../src/sha2_256.h -cflags $CFLAGS
add_files ../src/sha2_512.h -cflags $CFLAGS
add_files ../src/sha2.cpp -cflags $CFLAGS

add_files -tb ../tb/tests/tests.h -cflags $CFLAGS
add_files -tb ../tb/tests/utils.h -cflags $CFLAGS
add_files -tb ../tb/main.cpp -cflags $CFLAGS

open_solution "BASIC"

if { $board == "zynq" } {

    # Xilinx Zynq ZC702
    set_part {xc7z020clg484-1} -tool vivado

} elseif { $board == "zynqmp102" } {

    # Xilinx ZynqMP ZCU102
    set_part {xczu9eg-ffvb1156-2-e} -tool vivado

}

create_clock -period 3.30 -name default

config_interface -m_axi_offset off -register_io off

config_schedule -relax_ii_for_timing

csim_design -clean

csynth_design

export_design -format ip_catalog

exit
