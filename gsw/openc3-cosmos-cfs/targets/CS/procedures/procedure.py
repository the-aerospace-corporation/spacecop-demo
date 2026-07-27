# Script Runner test script
cmd("CS EXAMPLE")
wait_check("CS STATUS BOOL == 'FALSE'", 5)
