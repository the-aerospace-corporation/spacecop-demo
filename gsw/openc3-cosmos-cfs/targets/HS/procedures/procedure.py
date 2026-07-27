# Script Runner test script
cmd("HS EXAMPLE")
wait_check("HS STATUS BOOL == 'FALSE'", 5)
