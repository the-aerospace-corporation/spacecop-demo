# Script Runner test script
cmd("LC EXAMPLE")
wait_check("LC STATUS BOOL == 'FALSE'", 5)
