# Script Runner test script
cmd("SC EXAMPLE")
wait_check("SC STATUS BOOL == 'FALSE'", 5)
