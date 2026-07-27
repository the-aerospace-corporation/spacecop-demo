# Script Runner test script
cmd("FM EXAMPLE")
wait_check("FM STATUS BOOL == 'FALSE'", 5)
