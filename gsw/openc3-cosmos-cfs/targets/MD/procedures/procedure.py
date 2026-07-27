# Script Runner test script
cmd("MD EXAMPLE")
wait_check("MD STATUS BOOL == 'FALSE'", 5)
