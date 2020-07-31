#
# Makefile
#

# For now just zynqmp102
all: zynqmp102

zynq:
	vivado_hls -f script.tcl zynq sha2

zynqmp102:
	vivado_hls -f script.tcl zynqmp102 sha2

zynqmp106:
	vivado_hls -f script.tcl zynqmp106 sha2

results:
	@echo "Clock:"
	@echo -n " -- Target:          "
	@$(call get_first,TargetClockPeriod,./project_zynqmp102/BASIC/syn/report/csynth.xml)
	@echo -n " -- Estimated:       "
	@$(call get_first,EstimatedClockPeriod,./project_zynqmp102/BASIC/syn/report/csynth.xml)
	@echo "Latency: "
	@echo -n " -- Best-case:       "
	@$(call get_first,Best-caseLatency,./project_zynqmp102/BASIC/syn/report/csynth.xml)
	@echo -n " -- Average-case:    "
	@$(call get_first,Average-caseLatency,./project_zynqmp102/BASIC/syn/report/csynth.xml)
	@echo -n " -- Worst-case:      "
	@$(call get_first,Worst-caseLatency,./project_zynqmp102/BASIC/syn/report/csynth.xml)
	@echo "Resources: "
	@echo -n " -- FF_USAGE:        "
	@$(call get_first,FF,./project_zynqmp102/BASIC/syn/report/csynth.xml) | tr '\n' '\0'
	@echo -n " out of "
	@$(call get_second,FF,./project_zynqmp102/BASIC/syn/report/csynth.xml)
	@echo -n " -- LUT_USAGE:       "
	@$(call get_first,LUT,./project_zynqmp102/BASIC/syn/report/csynth.xml) | tr '\n' '\0'
	@echo -n " out of "
	@$(call get_second,LUT,./project_zynqmp102/BASIC/syn/report/csynth.xml)
	@echo -n " -- DSP_USAGE:       "
	@$(call get_first,DSP48E,./project_zynqmp102/BASIC/syn/report/csynth.xml) | tr '\n' '\0'
	@echo -n " out of "
	@$(call get_second,DSP48E,./project_zynqmp102/BASIC/syn/report/csynth.xml)
	@echo -n " -- BRAM_USAGE:      "
	@$(call get_first,BRAM_18K,./project_zynqmp102/BASIC/syn/report/csynth.xml) | tr '\n' '\0'
	@echo -n " out of "
	@$(call get_second,BRAM_18K,./project_zynqmp102/BASIC/syn/report/csynth.xml)

clean:
	rm -rf project_* *.log *.jou

# Functions

define get_first
	grep -m1 "<$(1)>.*</$(1)>" $(2) | cut -d">" -f2 | cut -d"<" -f1
endef

define get_second
	grep -m2 "<$(1)>.*</$(1)>" $(2) | tail -n 1 | cut -d">" -f2 | cut -d"<" -f1
endef
