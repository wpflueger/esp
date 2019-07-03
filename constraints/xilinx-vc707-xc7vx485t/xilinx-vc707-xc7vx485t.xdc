# --- Input clock is defined in MIG autogenerated constraints

# Recover elaborated clock name
set clkm_elab [get_clocks -of_objects [get_nets clkm]]
set refclk_elab [get_clocks -of_objects [get_nets chip_refclk]]

# Declare asynchronous clocks
set_clock_groups -asynchronous -group [get_clocks ${clkm_elab}] -group [get_clocks ${refclk_elab}]


# --- False paths
set_false_path -to [get_ports {led[*]}]
set_false_path -from [get_ports {button[*]}]
set_false_path -from [get_ports reset]
set_false_path -from [get_ports switch*]
set_false_path -to [get_ports switch*]

# Pin and IO property

set_property IOSTANDARD LVCMOS18 [get_ports reset]
set_property PACKAGE_PIN AV40 [get_ports reset]

set_property PACKAGE_PIN AM39 [get_ports {led[0]}]
set_property PACKAGE_PIN AN39 [get_ports {led[1]}]
set_property PACKAGE_PIN AR37 [get_ports {led[2]}]
set_property PACKAGE_PIN AT37 [get_ports {led[3]}]
set_property PACKAGE_PIN AR35 [get_ports {led[4]}]
set_property PACKAGE_PIN AP41 [get_ports {led[5]}]
set_property PACKAGE_PIN AP42 [get_ports {led[6]}]

set_property PACKAGE_PIN AU36 [get_ports uart_txd]
set_property PACKAGE_PIN AT32 [get_ports uart_ctsn]
set_property PACKAGE_PIN AU33 [get_ports uart_rxd]
set_property PACKAGE_PIN AR34 [get_ports uart_rtsn]

set_property PACKAGE_PIN AP40 [get_ports {button[0]}]
set_property PACKAGE_PIN AR40 [get_ports {button[1]}]
set_property PACKAGE_PIN AV39 [get_ports {button[2]}]
set_property PACKAGE_PIN AU38 [get_ports {button[3]}]
set_property PACKAGE_PIN AV30 [get_ports {switch[0]}]
set_property PACKAGE_PIN AY33 [get_ports {switch[1]}]
set_property PACKAGE_PIN BA31 [get_ports {switch[2]}]
set_property PACKAGE_PIN BA32 [get_ports {switch[3]}]
set_property PACKAGE_PIN AW30 [get_ports {switch[4]}]

set_property IOSTANDARD LVCMOS18 [get_ports uart_*]
set_property IOSTANDARD LVCMOS18 [get_ports led*]
set_property IOSTANDARD LVCMOS18 [get_ports button*]
set_property IOSTANDARD LVCMOS18 [get_ports switch*]

# --- UART
# Inputs
set_input_delay -clock [get_clocks -include_generated_clocks CLKFB*] -max 3.000 [get_ports uart_rxd]
set_input_delay -clock [get_clocks -include_generated_clocks CLKFB*] -min -add_delay 1.000 [get_ports uart_rxd]
set_input_delay -clock [get_clocks -include_generated_clocks CLKFB*] -max 3.000 [get_ports uart_ctsn]
set_input_delay -clock [get_clocks -include_generated_clocks CLKFB*] -min -add_delay 1.000 [get_ports uart_ctsn]

# Outputs
set_output_delay -clock [get_clocks -include_generated_clocks CLKFB*] -max 1.000 [get_ports uart_txd]
set_output_delay -clock [get_clocks -include_generated_clocks CLKFB*] -min -add_delay -1.000 [get_ports uart_txd]
set_output_delay -clock [get_clocks -include_generated_clocks CLKFB*] -max 1.000 [get_ports uart_rtsn]
set_output_delay -clock [get_clocks -include_generated_clocks CLKFB*] -min -add_delay -1.000 [get_ports uart_rtsn]
