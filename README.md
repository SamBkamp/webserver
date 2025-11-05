# Webserver for my personal site

why use something fancy like apache or nginx to serve my static files? Thats for losers!!

Nothing says #developer like serving your CV on a webserver you wrote from scratch.

Currently it is single threaded, managed by a bunch of poll calls to each socket currently open. This removes a lot of the socket creation/deletion overhead, but of course also constrains you to the speed of your machines CPU without taking advantage of all of its cores. Don't use this if your server has more than 1 core/thread, or do, I'm just a readme.


### weird stuff

theres some weird stuff in this codebase that im logging here so I can come back to it later to un-weird it.

- populate_http_response() uses malloc to dedicate space on the heap for the http response code messages (OK, NOT FOUND, etc.). Because this gets returned to the caller and the caller then calls the send function, its super easy to forget to free this, and this happens for each request so this is a huge risk. Currently there is a free() in the send function but this is a bandaid solution. In my opinion the larger issue here is that the populate function needs to determine the string based on the code (ie the string is hard coded based on the code). This is sub-par. The reason I applied a bandaid solution is because I want to convert this to a kind of look up table of response code text, maybe allocated in the binary itsellf or something. Eventually.