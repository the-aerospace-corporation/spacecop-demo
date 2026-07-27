# Script Runner test script
cmd("MM EXAMPLE")
wait_check("MM STATUS BOOL == 'FALSE'", 5)
