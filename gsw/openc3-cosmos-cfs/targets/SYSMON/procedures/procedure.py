# Script Runner test script
cmd("SYSMON EXAMPLE")
wait_check("SYSMON STATUS BOOL == 'FALSE'", 5)
