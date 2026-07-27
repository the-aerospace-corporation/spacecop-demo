# Script Runner test script
cmd("SCH EXAMPLE")
wait_check("SCH STATUS BOOL == 'FALSE'", 5)
