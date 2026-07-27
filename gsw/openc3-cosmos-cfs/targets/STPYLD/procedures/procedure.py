# Script Runner test script
cmd("STPYLD EXAMPLE")
wait_check("STPYLD STATUS BOOL == 'FALSE'", 5)
