# Script Runner test script
cmd("CFE EXAMPLE")
wait_check("CFE STATUS BOOL == 'FALSE'", 5)
