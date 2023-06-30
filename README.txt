README

To install openssl libraries in Ubuntu use 
sudo apt-get install libssl-dev

To generate your own certificate use this command
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem

Compiling the code
Server : gcc -Wall -o ssl-server SSL-Server.c -L/usr/lib -lssl –lcrypto
Client : gcc -Wall -o ssl-client SSL-Client.c -L/usr/lib -lssl -lcrypto

Run the program
Server : sudo ./ssl-server <portnum> 
Client : ./ssl-client <hostname> <portnum> 