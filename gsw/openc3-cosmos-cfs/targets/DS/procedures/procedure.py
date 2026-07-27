# Script Runner test script
cmd("DS EXAMPLE")
wait_check("DS STATUS BOOL == 'FALSE'", 5)
