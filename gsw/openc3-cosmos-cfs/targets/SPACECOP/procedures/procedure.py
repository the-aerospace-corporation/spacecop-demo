# Script Runner test script
cmd("SPACECOP EXAMPLE")
wait_check("SPACECOP STATUS BOOL == 'FALSE'", 5)
