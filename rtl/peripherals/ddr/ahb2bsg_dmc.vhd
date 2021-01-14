------------------------------------------------------------------------------
--  This file is a part of the GRLIB VHDL IP LIBRARY
--  Copyright (C) 2003 - 2008, Gaisler Research
--  Copyright (C) 2008 - 2014, Aeroflex Gaisler
--  Copyright (C) 2015 - 2016, Cobham Gaisler
--
--  This program is free software; you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation; either version 2 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program; if not, write to the Free Software
--  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
--  Porting for UltraScale+ FPGA device
--
--  Copyright (C) 2018 - 2019, Columbia University
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use work.all;
use work.ahb2mig_7series_pkg.all;
use work.amba.all;
use work.stdlib.all;
use work.devices.all;
use work.config_types.all;
use work.config.all;
library std;
use std.textio.all;

entity ahb2bsg_dmc is
  port(
    hindex          : in  integer;
    haddr           : in  integer;
    hmask           : in  integer;
    lpddr_ck_p      : out std_logic;
    lpddr_ck_n      : out std_logic;
    lpddr_cke       : out std_logic;
    lpddr_ba        : out std_logic_vector(2 downto 0);
    lpddr_addr      : out std_logic_vector(15 downto 0);
    lpddr_cs_n      : out std_logic;
    lpddr_ras_n     : out std_logic;
    lpddr_cas_n     : out std_logic;
    lpddr_we_n      : out std_logic;
    lpddr_reset_n   : out std_logic;
    lpddr_odt       : out std_logic;
    lpddr_dm_oen    : out std_logic_vector(3 downto 0);
    lpddr_dm        : out std_logic_vector(3 downto 0);
    lpddr_dqs_p_oen : out std_logic_vector(3 downto 0);
    lpddr_dqs_p_ien : out std_logic_vector(3 downto 0);
    lpddr_dqs_p_o   : out std_logic_vector(3 downto 0);
    lpddr_dqs_p_i   : in  std_logic_vector(3 downto 0);
    lpddr_dqs_n_oen : out std_logic_vector(3 downto 0);
    lpddr_dqs_n_ien : out std_logic_vector(3 downto 0);
    lpddr_dqs_n_o   : out std_logic_vector(3 downto 0);
    lpddr_dqs_n_i   : in  std_logic_vector(3 downto 0);
    lpddr_dq_oen    : out std_logic_vector(31 downto 0);
    lpddr_dq_o      : out std_logic_vector(31 downto 0);
    lpddr_dq_i      : in  std_logic_vector(31 downto 0);
    ddr_cfg0        : in  std_logic_vector(31 downto 0);
    ddr_cfg1        : in  std_logic_vector(31 downto 0);
    ddr_cfg2        : in  std_logic_vector(31 downto 0);
    ahbso           : out ahb_slv_out_type;
    ahbsi           : in  ahb_slv_in_type;
    calib_done      : out std_logic;
    ui_clk          : in  std_logic;
    ui_rstn         : in  std_logic;
    phy_clk_1x      : in  std_logic;
    phy_clk_2x      : in  std_logic;
    phy_rstn        : in  std_logic
    );
end;

architecture rtl of ahb2bsg_dmc is

  component bsg_dmc_wrap is
    generic (
      ui_addr_width_p    : integer := 28;
      ui_data_width_p    : integer := 64;
      ui_burst_length_p  : integer := 8;
      dq_data_width_p    : integer := 32;
      cmd_afifo_depth_p  : integer := 4;
      cmd_sfifo_depth_p  : integer := 4
      );
    port (
      -- User interface input signals
      app_addr            : in  std_logic_vector(ui_addr_width_p - 1 downto 0);
      app_cmd             : in  std_logic_vector(2 downto 0);
      app_en              : in  std_logic;
      app_wdf_data        : in  std_logic_vector(ui_data_width_p - 1 downto 0);
      app_wdf_end         : in  std_logic;
      app_wdf_mask        : in  std_logic_vector((ui_data_width_p / 8) - 1 downto 0);
      app_wdf_wren        : in  std_logic;
      -- User interface output signals
      app_rd_data         : out std_logic_vector(ui_data_width_p - 1 downto 0);
      app_rd_data_end     : out std_logic;
      app_rd_data_valid   : out std_logic;
      app_rdy             : out std_logic;
      app_wdf_rdy         : out std_logic;
      -- Status signal
      init_calib_complete : out std_logic;
      -- Tile clock == DDR clock (200 MHz rotated 90 degrees) and tile synchronous reset
      ui_clk_i            : in  std_logic;
      ui_reset_i          : in  std_logic;
      -- PHY 2x clock (400 MHz) and 1x clock (200 MHz) with synchronous reset
      dfi_clk_2x_i        : in  std_logic;
      dfi_clk_1x_i        : in  std_logic;
      dfi_reset_i         : in  std_logic;
      -- Command and Address interface
      ddr_ck_p_o          : out std_logic;
      ddr_ck_n_o          : out std_logic;
      ddr_cke_o           : out std_logic;
      ddr_ba_o            : out std_logic_vector(2 downto 0);
      ddr_addr_o          : out std_logic_vector(15 downto 0);
      ddr_cs_n_o          : out std_logic;
      ddr_ras_n_o         : out std_logic;
      ddr_cas_n_o         : out std_logic;
      ddr_we_n_o          : out std_logic;
      ddr_reset_n_o       : out std_logic;
      ddr_odt_o           : out std_logic;
      -- Data interface
      ddr_dm_oen_o        : out std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dm_o            : out std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dqs_p_oen_o     : out std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dqs_p_ien_o     : out std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dqs_p_o         : out std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dqs_p_i         : in  std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dqs_n_oen_o     : out std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dqs_n_ien_o     : out std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dqs_n_o         : out std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dqs_n_i         : in  std_logic_vector((dq_data_width_p / 8) - 1 downto 0);
      ddr_dq_oen_o        : out std_logic_vector(dq_data_width_p - 1 downto 0);
      ddr_dq_o            : out std_logic_vector(dq_data_width_p - 1 downto 0);
      ddr_dq_i            : in  std_logic_vector(dq_data_width_p - 1 downto 0);
      -- Delay line configuration
      delay_sel_i         : in  std_logic_vector(3 downto 0);
      -- DDR controller configuration
      trefi_i             : in  std_logic_vector(12 downto 0);
      tmrd_i              : in  std_logic_vector(3 downto 0);
      trfc_i              : in  std_logic_vector(3 downto 0);
      trc_i               : in  std_logic_vector(3 downto 0);
      trp_i               : in  std_logic_vector(3 downto 0);
      tras_i              : in  std_logic_vector(3 downto 0);
      trrd_i              : in  std_logic_vector(3 downto 0);
      trcd_i              : in  std_logic_vector(3 downto 0);
      twr_i               : in  std_logic_vector(3 downto 0);
      twtr_i              : in  std_logic_vector(3 downto 0);
      trtp_i              : in  std_logic_vector(3 downto 0);
      tcas_i              : in  std_logic_vector(3 downto 0);
      col_width_i         : in  std_logic_vector(3 downto 0);
      row_width_i         : in  std_logic_vector(3 downto 0);
      bank_width_i        : in  std_logic_vector(1 downto 0);
      bank_pos_i          : in  std_logic_vector(5 downto 0);
      dqs_sel_cal_i       : in  std_logic_vector(2 downto 0);
      init_cycles_i       : in  std_logic_vector(15 downto 0)
      );
  end component bsg_dmc_wrap;

  signal trefi_ext : std_logic_vector(12 downto 0);

  signal ui_rst : std_logic;
  signal phy_rst : std_logic;

  signal ddr_dqs_p_ien : std_logic_vector(3 downto 0);
  signal ddr_dqs_p_i   : std_logic_vector(3 downto 0);
  signal ddr_dqs_n_ien : std_logic_vector(3 downto 0);
  signal ddr_dqs_n_i   : std_logic_vector(3 downto 0);

  type bstate_type is (idle, start, read_cmd, read_data, read_wait, read_output, write_cmd, write_burst);

  constant maxburst   : integer := 8;
  constant maxmigcmds : integer := nbrmaxmigcmds(AHBDW);
  constant wrsteps    : integer := log2(32);
  constant wrmask     : integer := log2(32/8);

  signal hconfig : ahb_config_type;

  type reg_type is record
    bstate          : bstate_type;
    cmd             : std_logic_vector(2 downto 0);
    cmd_en          : std_logic;
    wr_en           : std_logic;
    wr_end          : std_logic;
    cmd_count       : unsigned(31 downto 0);
    wr_count        : unsigned(31 downto 0);
    rd_count        : unsigned(31 downto 0);
    hready          : std_logic;
    hwrite          : std_logic;
    hwdata_burst    : std_logic_vector(AHBDW * maxmigcmds - 1 downto 0);
    mask_burst      : std_logic_vector(AHBDW/8 * maxmigcmds - 1 downto 0);
    htrans          : std_logic_vector(1 downto 0);
    hburst          : std_logic_vector(2 downto 0);
    hsize           : std_logic_vector(2 downto 0);
    hrdata          : std_logic_vector(AHBDW - 1 downto 0);
    haddr           : std_logic_vector(31 downto 0);
    haddr_start     : std_logic_vector(31 downto 0);
    haddr_offset    : std_logic_vector(31 downto 0);
    hmaster         : std_logic_vector(3 downto 0);
    int_buffer      : unsigned(AHBDW * maxmigcmds - 1 downto 0);
    rd_buffer       : unsigned(AHBDW * maxmigcmds - 1 downto 0);
    wdf_data_buffer : std_logic_vector(AHBDW - 1 downto 0);
    wdf_mask_buffer : std_logic_vector(AHBDW/8 - 1 downto 0);
    migcommands     : integer;
    nxt             : std_logic;
  end record;

  type mig_in_type is record
    app_addr     : std_logic_vector(27 downto 0);
    app_cmd      : std_logic_vector(2 downto 0);
    app_en       : std_logic;
    app_hi_pri   : std_logic;
    app_wdf_data : std_logic_vector(AHBDW - 1 downto 0);
    app_wdf_end  : std_logic;
    app_wdf_mask : std_logic_vector(AHBDW / 8 - 1 downto 0);
    app_wdf_wren : std_logic;
  end record;

  type mig_out_type is record
    app_rd_data       : std_logic_vector(AHBDW - 1 downto 0);
    app_rd_data_end   : std_logic;
    app_rd_data_valid : std_logic;
    app_rdy           : std_logic;
    app_wdf_rdy       : std_logic;
  end record;

  signal rin, r, rnxt, rnxtin : reg_type;
  signal migin                : mig_in_type;
  signal migout, migoutraw    : mig_out_type;

begin

  hconfig <= (
    0      => ahb_device_reg (VENDOR_GAISLER, GAISLER_MIG_7SERIES, 0, 0, 0),
    4      => ahb_membar(haddr, '1', '1', hmask),
    others => zero32);

  comb : process(ui_rstn, r, rin, ahbsi, migout, rnxt, hindex)

    -- Design temp variables
    variable v, vnxt                : reg_type;
    variable writedata              : std_logic_vector(255 downto 0);
    variable wmask                  : std_logic_vector(AHBDW/4-1 downto 0);
    variable shift_steps            : natural;
    variable hrdata_shift_steps     : natural;
    variable steps_write            : unsigned(31 downto 0);
    variable shift_steps_write      : natural;
    variable shift_steps_write_mask : natural;
    variable startaddress           : unsigned(v.haddr'length-1 downto 0);
    variable start_address          : std_logic_vector(v.haddr'length-1 downto 0);
    variable step_offset            : unsigned(steps_write'length-1 downto 0);
    variable haddr_offset           : unsigned(steps_write'length-1 downto 0);

  begin

    -- Make all register visible for the statemachine
    v := r; vnxt := rnxt;

    -- workout the start address in AHB2MIG buffer based upon
    startaddress := resize(unsigned(unsigned(ahbsi.haddr(ahbsi.haddr'left-2 downto 8)) & "00000"), startaddress'length);

    -- Adjust offset in memory buffer
    startaddress  := resize(startaddress + unsigned(unsigned(ahbsi.haddr(7 downto 6))&"000"), startaddress'length);
    start_address := std_logic_vector(startaddress);

    -- Workout local offset to be able to adust for warp-around
    haddr_offset := unsigned(r.haddr_start) - unsigned(unsigned(r.haddr_offset(r.haddr_offset'length-1 downto 6))&"000000");
    step_offset  := resize(unsigned(haddr_offset(7 downto 6)&"0000"), step_offset'length);

    -- Fetch AMBA Commands
    if ((ahbsi.hsel(hindex) and ahbsi.htrans(1) and ahbsi.hready and not ahbsi.htrans(0)) = '1'
        and (ahbsi.hwrite = '0' or ahbsi.hwrite = '1')) then

      vnxt.cmd_count := (others => '0');
      vnxt.wr_count  := (others => '0');
      vnxt.rd_count  := (others => '0');
      vnxt.hrdata    := (others => '0');

      -- Clear old pointers and MIG command signals
      vnxt.cmd          := (others => '0');
      vnxt.cmd_en       := '0';
      vnxt.wr_en        := '0';
      vnxt.wr_end       := '0';
      vnxt.hwrite       := '0';
      vnxt.hwdata_burst := (others => '0');
      vnxt.mask_burst   := (others => '0');

      -- Hold info regarding transaction and execute
      vnxt.hburst                        := ahbsi.hburst;
      vnxt.hwrite                        := ahbsi.hwrite;
      vnxt.hsize                         := ahbsi.hsize;
      vnxt.hmaster                       := ahbsi.hmaster;
      vnxt.hready                        := '0';
      vnxt.htrans                        := ahbsi.htrans;
      vnxt.bstate                        := start;
      vnxt.haddr                         := start_address;
      vnxt.haddr_start                   := ahbsi.haddr;
      vnxt.haddr_offset                  := ahbsi.haddr;
      vnxt.cmd(2 downto 0)               := (others => '0');
      vnxt.cmd(0)                        := not ahbsi.hwrite;
      if (r.bstate = idle) then vnxt.nxt := '0'; else vnxt.nxt := '1'; end if;

      -- Clear some old stuff
      vnxt.int_buffer      := (others => '0');
      vnxt.rd_buffer       := (others => '0');
      vnxt.wdf_data_buffer := (others => '0');
      vnxt.wdf_mask_buffer := (others => '0');

    end if;

    case r.bstate is
      when idle =>
        -- Clear old pointers and MIG command signals
        v.cmd          := (others => '0');
        v.cmd_en       := '0';
        v.wr_en        := '0';
        v.wr_end       := '0';
        v.hready       := '1';
        v.hwrite       := '0';
        v.hwdata_burst := (others => '0');
        v.mask_burst   := (others => '0');
        v.rd_count     := (others => '0');

        vnxt.cmd          := (others => '0');
        vnxt.cmd_en       := '0';
        vnxt.wr_en        := '0';
        vnxt.wr_end       := '0';
        vnxt.hready       := '1';
        vnxt.hwrite       := '0';
        vnxt.hwdata_burst := (others => '0');
        vnxt.mask_burst   := (others => '0');
        vnxt.rd_count     := (others => '0');
        vnxt.wr_count     := (others => '0');
        vnxt.cmd_count    := (others => '0');

        -- Check if this is a single or burst transfer (and not a BUSY transfer)
        if ((ahbsi.hsel(hindex) and ahbsi.htrans(1) and ahbsi.hready) = '1'
            and (ahbsi.hwrite = '0' or ahbsi.hwrite = '1')) then

          -- Hold info regarding transaction and execute
          v.hburst       := ahbsi.hburst;
          v.hwrite       := ahbsi.hwrite;
          v.hsize        := ahbsi.hsize;
          v.hmaster      := ahbsi.hmaster;
          v.hready       := '0';
          v.htrans       := ahbsi.htrans;
          v.bstate       := start;
          v.haddr        := start_address;
          v.haddr_start  := ahbsi.haddr;
          v.haddr_offset := ahbsi.haddr;
          v.cmd          := (others => '0');
          v.cmd(0)       := not ahbsi.hwrite;
        end if;

      when start =>
        v.migcommands := nbrmigcmds(r.hwrite, r.hsize, ahbsi.htrans, step_offset, AHBDW);

        -- Check if a write command shall be issued to the DDR4 memory
        if r.hwrite = '1' then

          wmask     := (others => '0');
          writedata := (others => '0');

          if ((ahbsi.htrans /= HTRANS_SEQ) or ((ahbsi.htrans = HTRANS_SEQ) and (r.rd_count > 0) and (r.rd_count <= maxburst))) then
            -- work out how many steps we need to shift the input
            steps_write            := ahbselectdatanoreplicastep(r.haddr_start(7 downto 2), r.hsize(2 downto 0)) + step_offset;
            shift_steps_write      := to_integer(shift_left(steps_write, wrsteps));
            shift_steps_write_mask := to_integer(shift_left(steps_write, wrmask));

            -- generate mask for complete burst (only need to use addr[3:0])
            wmask        := ahbselectdatanoreplicamask(r.haddr_start(6 downto 0), r.hsize(2 downto 0));
            v.mask_burst := r.mask_burst or std_logic_vector(shift_left(resize(unsigned(wmask), r.mask_burst'length), shift_steps_write_mask));

            -- fetch all wdata before write to memory can begin (only supports upto 128bits i.e. addr[4:0]
            writedata(AHBDW-1 downto 0) := ahbselectdatanoreplica(ahbsi.hwdata(AHBDW-1 downto 0), r.haddr_start(4 downto 0), r.hsize(2 downto 0));
            v.hwdata_burst              := r.hwdata_burst or std_logic_vector(shift_left(resize(unsigned(writedata), v.hwdata_burst'length), shift_steps_write));

            v.haddr_start := ahbsi.haddr;
          end if;

          -- Check if this is a cont burst longer than internal buffer
          if (ahbsi.htrans = HTRANS_SEQ) then
            if (r.rd_count < maxburst-1) then
              v.hready := '1';
            else
              v.hready := '0';
            end if;
            if (r.rd_count >= maxburst) then
              if (r.htrans = HTRANS_SEQ) then
                v.bstate := write_cmd;
              end if;
              v.htrans := ahbsi.htrans;
            end if;
          else
            v.bstate := write_cmd;
            v.htrans := ahbsi.htrans;
          end if;

        -- Else issue a read command when ready
        else
          if migout.app_rdy = '1' and migout.app_wdf_rdy = '1' then
            v.cmd       := "001";
            v.bstate    := read_cmd;
            v.htrans    := ahbsi.htrans;
            v.cmd_count := to_unsigned(0, v.cmd_count'length);
          end if;
        end if;

      when write_cmd =>
        -- Check if burst has ended due to max size burst
        if (ahbsi.htrans /= HTRANS_SEQ) then
          v.htrans := (others => '0');
        end if;

        -- Stop when addr and write command is accepted by mig
        if (r.wr_count >= r.migcommands) and (r.cmd_count >= r.migcommands) then
          if (r.htrans /= HTRANS_SEQ) then
            -- Check if we have a pending transaction
            if (vnxt.nxt = '1') then
              v        := vnxt;
              vnxt.nxt := '0';
            else
              v.bstate := idle;
            end if;
          else  -- Cont burst and work out new offset for next write command
            v.bstate := write_burst;
            v.hready := '1';
          end if;
        end if;

      when write_burst =>
        v.bstate       := start;
        v.hready       := '0';
        v.hwdata_burst := (others => '0');
        v.mask_burst   := (others => '0');
        v.haddr        := start_address;
        v.haddr_offset := ahbsi.haddr;

        -- Check if we have a pending transaction
        if (vnxt.nxt = '1') then
          v        := vnxt;
          vnxt.nxt := '0';
        end if;

      when read_cmd =>
        v.hready   := '0';
        v.rd_count := (others => '0');
        -- stop when read command is accepted ny mig.
        if (r.cmd_count >= r.migcommands) then
          v.bstate := read_data;
        --v.int_buffer := (others => '0');
        end if;

      when read_data =>
        -- We are not ready yet so issue a read command to the memory controller
        v.hready := '0';

        -- If read data is valid store data in buffers
        if (migout.app_rd_data_valid = '1') then
          v.rd_count := r.rd_count + 1;
          -- Viviado seems to misinterpet the following shift construct and
          -- therefore changed to a if-else statement
          --v.int_buffer := r.int_buffer or shift_left( resize(unsigned(migout.app_rd_data),r.int_buffer'length),
          --                                           to_integer(shift_left(r.rd_count,9)));
          if (r.rd_count = 0) then
            v.int_buffer(AHBDW - 1 downto 0) := unsigned(migout.app_rd_data);
          elsif (r.rd_count = 1) then
            v.int_buffer(2 * AHBDW - 1 downto AHBDW) := unsigned(migout.app_rd_data);
          elsif (AHBDW > 64) then
            if (r.rd_count = 2) then
              v.int_buffer(3 * AHBDW - 1 downto 2 * AHBDW) := unsigned(migout.app_rd_data);
            else
              v.int_buffer(4 * AHBDW - 1 downto 3 * AHBDW) := unsigned(migout.app_rd_data);
            end if;
          end if;
        end if;

        if (r.rd_count >= r.migcommands) then
          v.rd_buffer := r.int_buffer;
          v.bstate    := read_output;
          v.rd_count  := to_unsigned(0, v.rd_count'length);
        end if;

      when read_output =>

        -- Data is fetched from memory and ready to be transfered
        v.hready := '1';

        -- uses the "wr_count" signal to keep track of number of bytes output'd to AHB
        -- Select correct 32bit/64bit/128bit to output
        v.hrdata := ahbselectdatanoreplicaoutput(r.haddr_start(7 downto 0), r.wr_count, r.hsize, r.rd_buffer, r.wr_count, true);

        -- Count number of bytes send
        v.wr_count := r.wr_count + 1;

        -- Check if this was the last transaction
        if (r.wr_count >= maxburst-1) then
          v.bstate := read_wait;
        end if;

        -- Check if transfer was interrupted or no burst
        if (ahbsi.htrans = HTRANS_IDLE) or ((ahbsi.htrans = HTRANS_NONSEQ) and (r.wr_count < maxburst)) then
          v.bstate    := read_wait;
          v.wr_count  := (others => '0');
          v.rd_count  := (others => '0');
          v.cmd_count := (others => '0');

          -- Check if we have a pending transaction
          if (vnxt.nxt = '1') then
            v        := vnxt;
            vnxt.nxt := '0';
            v.bstate := start;
          end if;
        end if;

      when read_wait =>
        if ((r.wr_count >= maxburst) and (ahbsi.htrans = HTRANS_SEQ)) then
          v.hready       := '0';
          v.bstate       := start;
          v.haddr_start  := ahbsi.haddr;
          v.haddr        := start_address;
          v.haddr_offset := ahbsi.haddr;
        else
          -- Check if we have a pending transaction
          if (vnxt.nxt = '1') then
            v        := vnxt;
            vnxt.nxt := '0';
            v.bstate := start;
          else
            v.bstate := idle;
            v.hready := '1';
          end if;
        end if;

      when others =>
        v.bstate := idle;
    end case;

    if ((ahbsi.htrans /= HTRANS_SEQ) and (r.bstate = start)) then
      v.hready := '0';
    end if;

    if ui_rstn = '0' then
      v.bstate := idle; v.hready := '1'; v.cmd_en := '0'; v.wr_en := '0'; v.wr_end := '0';
    --v.wdf_mask_buffer := (others => '0');  v.wdf_data_buffer := (others => '0'); v.haddr := (others => '0');
    end if;

    rin    <= v;
    rnxtin <= vnxt;

  end process;

  ahbso.hready <= r.hready;
  ahbso.hresp  <= "00";                 --r.hresp;
  ahbso.hrdata <= ahbdrivedata(r.hrdata);

  migin.app_addr   <= r.haddr(27 downto 2) & "00";
  migin.app_cmd    <= r.cmd;
  migin.app_en     <= r.cmd_en;
  migin.app_hi_pri <= '0';

  migin.app_wdf_data <= r.wdf_data_buffer;
  migin.app_wdf_end  <= r.wr_end;
  migin.app_wdf_mask <= r.wdf_mask_buffer;
  migin.app_wdf_wren <= r.wr_en;

  ahbso.hconfig <= hconfig;
  ahbso.hirq    <= (others => '0');
  ahbso.hindex  <= hindex;
  ahbso.hsplit  <= (others => '0');

  regs : process(ui_clk)
  begin
    if rising_edge(ui_clk) then

      -- Copy variables into registers (Default values)
      r    <= rin;
      rnxt <= rnxtin;

      -- add extra pipe-stage for read data
      migout <= migoutraw;

      -- IDLE Clear
      if ((r.bstate = idle) or (r.bstate = read_wait)) then
        r.cmd_count <= (others => '0');
        r.wr_count  <= (others => '0');
        r.rd_count  <= (others => '0');
      end if;

      if (r.bstate = write_burst) then
        r.cmd_count <= (others => '0');
        r.wr_count  <= (others => '0');
        r.rd_count  <= to_unsigned(1, r.rd_count'length);
      end if;

      -- Read AHB write data
      if (r.bstate = start) and (r.hwrite = '1') then
        r.rd_count <= r.rd_count + 1;
      end if;

      -- Write command repsonse
      if r.bstate = write_cmd then

        if (r.cmd_count < 1) then
          r.cmd_en <= '1';
        end if;
        if (migoutraw.app_rdy = '1') and (r.cmd_en = '1') then
          r.cmd_count <= r.cmd_count + 1;
          if (r.cmd_count < r.migcommands-1) then
            r.haddr <= r.haddr + 8;
          end if;
          if (r.cmd_count >= r.migcommands-1) then
            r.cmd_en <= '0';
          end if;
        end if;

        if (r.wr_count < 1) then
          r.wr_en           <= '1';
          r.wr_end          <= '1';
          r.wdf_mask_buffer <= not r.mask_burst(AHBDW/8 - 1 downto 0);
          r.wdf_data_buffer <= r.hwdata_burst(AHBDW - 1 downto 0);
        end if;
        if (migoutraw.app_wdf_rdy = '1') and (r.wr_en = '1') then
          if (r.wr_count = 0) then
            r.wdf_mask_buffer <= not r.mask_burst(2 * AHBDW/8 - 1 downto AHBDW/8);
            r.wdf_data_buffer <= r.hwdata_burst(2 * AHBDW - 1 downto AHBDW);
          elsif (AHBDW > 64) then
            if (r.wr_count = 1) then
              r.wdf_mask_buffer <= not r.mask_burst(3 * AHBDW/8 - 1 downto 2 * AHBDW/8);
              r.wdf_data_buffer <= r.hwdata_burst(3 * AHBDW - 1 downto 2 * AHBDW);
            else
              r.wdf_mask_buffer <= not r.mask_burst(4 * AHBDW/8 - 1 downto 3 * AHBDW/8);
              r.wdf_data_buffer <= r.hwdata_burst(4 * AHBDW - 1 downto 3 * AHBDW);
            end if;
          else
            r.wdf_mask_buffer <= not r.mask_burst(2 * AHBDW/8 - 1 downto AHBDW/8);
            r.wdf_data_buffer <= r.hwdata_burst(2 * AHBDW - 1 downto AHBDW);
          end if;

          r.wr_count <= r.wr_count + 1;
          if (r.wr_count >= r.migcommands - 1) then
            r.wr_en  <= '0';
            r.wr_end <= '0';
          end if;
        end if;
      end if;

      -- Burst Write Wait
      if r.bstate = write_burst then
        r.cmd_count <= (others => '0');
        r.wr_count  <= (others => '0');
        r.rd_count  <= (others => '0');
      end if;

      -- Read command repsonse
      if r.bstate = read_cmd then
        if (r.cmd_count < 1) then
          r.cmd_en <= '1';
        end if;
        if (migoutraw.app_rdy = '1') and (r.cmd_en = '1') then
          r.cmd_count <= r.cmd_count + 1;
          if (r.cmd_count < r.migcommands-1) then
            r.haddr <= r.haddr + 8;
          end if;
          if (r.cmd_count >= r.migcommands-1) then
            r.cmd_en <= '0';
          end if;
        end if;

      end if;
    end if;
  end process;

  -- bsg_dmc reset is active high
  ui_rst <= not ui_rstn;
  phy_rst <= not phy_rstn;

  ddr_dqs_inout_gen: for i in 0 to 3 generate
    lpddr_dqs_p_ien(i) <= ddr_dqs_p_ien(i);
    lpddr_dqs_n_ien(i) <= ddr_dqs_n_ien(i);

    ddr_dqs_p_i(i) <= lpddr_dqs_p_i(i) when ddr_dqs_p_ien(i) = '0' else '0';
    ddr_dqs_n_i(i) <= lpddr_dqs_n_i(i) when ddr_dqs_n_ien(i) = '0' else '1';
  end generate ddr_dqs_inout_gen;

  bsg_dmc_wrap_1: bsg_dmc_wrap
    generic map (
      ui_addr_width_p    => 28,
      ui_data_width_p    => AHBDW,
      ui_burst_length_p  => maxburst,
      dq_data_width_p    => 32,
      cmd_afifo_depth_p  => 4,
      cmd_sfifo_depth_p  => 4)
    port map (
      app_addr            => migin.app_addr,
      app_cmd             => migin.app_cmd,
      app_en              => migin.app_en,
      app_wdf_data        => migin.app_wdf_data,
      app_wdf_end         => migin.app_wdf_end,
      app_wdf_mask        => migin.app_wdf_mask,
      app_wdf_wren        => migin.app_wdf_wren,
      app_rd_data         => migoutraw.app_rd_data,
      app_rd_data_end     => migoutraw.app_rd_data_end,
      app_rd_data_valid   => migoutraw.app_rd_data_valid,
      app_rdy             => migoutraw.app_rdy,
      app_wdf_rdy         => migoutraw.app_wdf_rdy,
      init_calib_complete => calib_done,
      ui_clk_i            => ui_clk,
      ui_reset_i          => ui_rst,
      dfi_clk_2x_i        => phy_clk_2x,
      dfi_clk_1x_i        => phy_clk_1x,
      dfi_reset_i         => phy_rst,
      ddr_ck_p_o          => lpddr_ck_p,
      ddr_ck_n_o          => lpddr_ck_n,
      ddr_cke_o           => lpddr_cke,
      ddr_ba_o            => lpddr_ba,
      ddr_addr_o          => lpddr_addr,
      ddr_cs_n_o          => lpddr_cs_n,
      ddr_ras_n_o         => lpddr_ras_n,
      ddr_cas_n_o         => lpddr_cas_n,
      ddr_we_n_o          => lpddr_we_n,
      ddr_reset_n_o       => lpddr_reset_n,
      ddr_odt_o           => lpddr_odt,
      ddr_dm_oen_o        => lpddr_dm_oen,
      ddr_dm_o            => lpddr_dm,
      ddr_dqs_p_oen_o     => lpddr_dqs_p_oen,
      ddr_dqs_p_ien_o     => ddr_dqs_p_ien,
      ddr_dqs_p_o         => lpddr_dqs_p_o,
      ddr_dqs_p_i         => ddr_dqs_p_i,
      ddr_dqs_n_oen_o     => lpddr_dqs_n_oen,
      ddr_dqs_n_ien_o     => ddr_dqs_n_ien,
      ddr_dqs_n_o         => lpddr_dqs_n_o,
      ddr_dqs_n_i         => ddr_dqs_n_i,
      ddr_dq_oen_o        => lpddr_dq_oen,
      ddr_dq_o            => lpddr_dq_o,
      ddr_dq_i            => lpddr_dq_i,
      delay_sel_i         => ddr_cfg0(3 downto 0),
      trefi_i             => trefi_ext,
      tmrd_i              => ddr_cfg0(19 downto 16),
      trfc_i              => ddr_cfg0(23 downto 20),
      trc_i               => ddr_cfg0(27 downto 24),
      trp_i               => ddr_cfg0(31 downto 28),
      tras_i              => ddr_cfg1(3 downto 0),
      trrd_i              => ddr_cfg1(7 downto 4),
      trcd_i              => ddr_cfg1(11 downto 8),
      twr_i               => ddr_cfg1(15 downto 12),
      twtr_i              => ddr_cfg1(19 downto 16),
      trtp_i              => ddr_cfg1(23 downto 20),
      tcas_i              => ddr_cfg1(27 downto 24),
      col_width_i         => ddr_cfg1(31 downto 28),
      row_width_i         => ddr_cfg2(3 downto 0),
      bank_width_i        => ddr_cfg2(5 downto 4),
      bank_pos_i          => ddr_cfg2(11 downto 6),
      dqs_sel_cal_i       => ddr_cfg2(14 downto 12),
      init_cycles_i       => ddr_cfg2(30 downto 15)
      );

  trefi_ext <= ddr_cfg2(31) & ddr_cfg0(15 downto 4);

end;
