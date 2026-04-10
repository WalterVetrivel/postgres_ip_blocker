## How to run
First, place the malicious_ip.txt file inside the /tmp directory. If you place it directly inside the project directory, chances are your extension will not have the permission to open it and the extension will just fail silently without any error messages and just won't block any of the IPs on the list (127.0.0.1) has been added to the list to help you test whether it blocks your IP correctly.

Then, open a terminal and run the command ```make -d``` and then ```sudo make install``` inside the project directory. This should compile and install the extension.

If you get an error due to your compiler not recognising your header files and the ClientAuthentication_hook_type typedef, then, run ```pg_config --includedir-server``` on a terminal and retry the make and install steps.

Next, open the file ```postgresql.conf```, generally located under ```/etc/postgresql/18/main```, and search for ```shared_preload_libraries```.

If ```shared_preload_libraries = ''```, then, just change it to, ```shared_preload_libraries = 'ip_blocker'```. If it already has some other extension, e.g., ```shared_preload_libraries = 'query_logger'```, then change it to ```shared_preload_libraries = 'ip_blocker, query_logger'```, where query_logger here is a placeholder for any pre-existing extension you might have added. Save the file once you're done editing.

Then, make sure you restart your running PostgreSQL service using ```sudo systemctl restart postgresql```.

Once you're done doing all of this, to test whether the extension works, have at least two terminals open. On the first one, run ```sudo tail -f /var/log/postgresql/postgresql-18-main.log``` to read the system logs related to PostgreSQL as you attempt to connect with our extension active. Then, on the other terminal, run ```psql -h 127.0.0.1 -U postgres```. If it prompts you for a password and you don't know the password, don't worry, you can easily reset it by first using ```sudo -u postgres psql```, and then running the query ```ALTER USER postgres WITH PASSWORD '12345';``` (replace 12345 with a password of your choice), exiting out of the PostgreSQL process using Ctrl + Z, and then re-running ```psql -h 127.0.0.1 -U postgres```.

Now, if the extension is working as intended, your connection should be blocked. If you don't want your connection to be blocked, edit the malicious_ip.txt file and remove the entries for 127.0.0.1 from the top (I added it twice while debugging an issue and forgot to remove it, and am now too lazy to do it), recompile the code with the ```make -d``` and ```sudo make install``` commands, restart PostgreSQL using ```sudo systemctl restart postgresql```, rerun ```sudo tail -f /var/log/postgresql/postgresql-18-main.log```, and finally, ```psql -h 127.0.0.1 -U postgres```. This time, if all goes well, your connection should not be blocked and you'll be able to use PostgreSQL normally (and if you look at the log, it'll say you're attempting to connect from 127.0.0.1 and such.

Try and build improvements to this, this is just a toy extension that doesn't really offer too much in the way of security. But it serves as a starting point for thinking about building security extensions for PostgreSQL. Happy coding!
