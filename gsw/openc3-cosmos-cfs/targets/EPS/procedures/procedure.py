# Script Runner test script
cmd("EPS EXAMPLE")
wait_check("EPS STATUS BOOL == 'FALSE'", 5)
