set where [file dirname [info script]]

set TDC_CELL [get_cells system_i/tdc_bank_0]
if {[string trim $TDC_CELL] != ""} {
    source [file join $where place_tdc.tcl]
}

set RO_CELL [get_cells system_i/ro_bank_0]
if {[string trim $RO_CELL] != ""} {
    source [file join $where place_ro.tcl]
}