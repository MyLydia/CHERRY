#! /bin/bash
echo "Content-Type: text/html"
echo 
echo "<html>"
echo "<head>"
read input
if [ -n "$input" ]; then
echo "<meta http-equiv=\"Refresh\" content=\"0; url=/boaform/admin/formLogin?$input\">"
fi
echo "<title>Login</title></head>"
echo "<body>"
echo "</body>"
echo "</html>"
