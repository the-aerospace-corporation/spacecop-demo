# Script Runner test script
cmd("CFDP EXAMPLE")
wait_check("CFDP STATUS BOOL == 'FALSE'", 5)
