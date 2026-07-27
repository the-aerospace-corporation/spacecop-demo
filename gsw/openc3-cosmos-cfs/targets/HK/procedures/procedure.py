# Script Runner test script
cmd("HK EXAMPLE")
wait_check("HK STATUS BOOL == 'FALSE'", 5)
