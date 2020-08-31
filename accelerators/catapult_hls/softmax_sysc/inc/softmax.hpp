// Copyright (c) 2011-2020 Columbia University, System Level Design Group
// SPDX-License-Identifier: Apache-2.0

#ifndef __SOFTMAX_HPP__
#define __SOFTMAX_HPP__

#include "softmax_fpdata.hpp"
#include "softmax_conf_info.hpp"
#include "softmax_debug_info.hpp"

#include "utils/esp_utils.hpp"
#include "utils/esp_handshake.hpp"
#include "core/systems/esp_dma_info.hpp"

template <class T, unsigned S>
struct plm_t {
public:
   T data[S];
};

// NoC-/Accelerator-interface dimensions
//#define DMA_WIDTH 64
#define DMA_SIZE SIZE_DWORD

typedef ac_int<DMA_WIDTH, false> dma_data_t;

// PLM and data dimensions
#define DATA_WIDTH 32
#define PLM_SIZE 128

#define BATCH_MAX 16

typedef plm_t<FPDATA_IN, PLM_SIZE> plm_in_t;
typedef plm_t<FPDATA_OUT, PLM_SIZE> plm_out_t;

SC_MODULE(softmax_sysc) {
public:

    //
    // Input ports
    //

    // Clock signal
    sc_in<bool> clk;

    // Reset signal
    sc_in<bool> rst;

    // Accelerator configuration
    sc_in<conf_info_t> conf_info;

    // Accelerator start signal
    sc_in<bool> conf_done;

    //
    // Output ports
    //

    // Computation complete
    sc_out<bool> acc_done;

    // Debug port
    sc_out<debug_info_t> debug;

    //
    // Data-transfer channels
    //

    // DMA read control
    Connections::Out<dma_info_t> dma_read_ctrl;

    // DMA write control
    Connections::Out<dma_info_t> dma_write_ctrl;

    // DMA read channel
    Connections::In<dma_data_t> dma_read_chnl;

    // DMA write channel
    Connections::Out<dma_data_t> dma_write_chnl;

    //
    // Process handshake
    //

    // Process synchronization
    sc_signal<bool> done;

    // Input <-> Computation
    handshake_t input_ready;

    // Computation <-> Output
    handshake_t output_ready;

    // Constructor
    SC_HAS_PROCESS(softmax_sysc);
    softmax_sysc(const sc_module_name& name)
        : sc_module(name)
          , clk("clk")
          , rst("rst")
          , conf_info("conf_info")
          , conf_done("conf_done")
          , acc_done("acc_done")
          , debug("debug")
          , dma_read_ctrl("dma_read_ctrl")
          , dma_write_ctrl("dma_write_ctrl")
          , dma_read_chnl("dma_read_chnl")
          , dma_write_chnl("dma_write_chnl")
          , done("done")
          , input_ready("input_ready")
          , output_ready("output_ready")
    {
        SC_CTHREAD(run, clk.pos());
        reset_signal_is(rst, false);
        // set_stack_size(0x400000);
    }

    //
    // Processes
    //
    // Single process config/loag/compute/store
    void run();

    //
    // Reset functions
    //

    // Reset DMA read channels
    inline void reset_dma_read();
    // Reset DMA write channels
    inline void reset_dma_write();
    // Reset the accelerator status
    inline void reset_accelerator_done();

    //
    // Functions
    //

    // The process is done
    inline void process_done();
    // The accelerator is done
    inline void accelerator_done();

    //
    // Private local memories
    //
    plm_in_t plm_in;
    plm_out_t plm_out;
};

#endif /* __SOFTMAX_HPP__ */
