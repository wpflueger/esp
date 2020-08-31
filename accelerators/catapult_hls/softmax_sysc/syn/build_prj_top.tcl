array set opt {
    # The 'csim' flag enables C simulation.
    # The 'hsynth' flag enables HLS.
    # The 'rtlsim' flag enables RTL simulation.
    # The 'lsynth' flag enables logic synthesis.
    # The 'debug' flag stops Catapult HLS before the architect step.
    # The 'hier' flag selects a micro-architecture:
    #   - 0: Single process
    #   - 1: Four processes with shared memories via MatchLib    [EXPERIMENTAL]
    #   - 2: Four processes with shared memories via ac_channels [EXPERIMENTAL]
    csim       1
    hsynth     1
    rtlsim     0
    lsynth     0
    debug      0
    hier       0
}

source ../../common/syn-templates/syn/common.tcl
source ./build_prj.tcl
