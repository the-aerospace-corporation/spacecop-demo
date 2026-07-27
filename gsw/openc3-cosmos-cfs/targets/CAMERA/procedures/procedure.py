# Script Runner test script
cmd("CAMERA EXAMPLE")
wait_check("CAMERA STATUS BOOL == 'FALSE'", 5)
