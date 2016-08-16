# roger


build  

          for windows  
            server: projects/roger/projects/msvc/roger/rserver.sln    
            client: projects/roger/projects/msvc/roger_client/roger.sln  
            please note that if you want to debug cilent in MS IDE, you must set debug parameter first 
            (ip and port in command arguments)
          
          for linux  
            server: projects/roger/projects/linux/makefile
            make example: make build=debug platform=x86_64
            or  
            server: projects/roger/projects/codeblocks/roger/roger.workspace
            
            client: to be writtern...
  
usage

          1, start server
          	./roger_server > /dev/null &
          
          2, start client
          	roger.exe ip port
          
          3, setup proxy on browser side   
          	http proxy address: http://127.0.0.1:8088/proxy.pac   
          	socks5 proxy address: 127.0.0.1 12122  

discussion group: QQ(452583496)



This is a protocol test project based upon wawo library, we are opposed to any violence and illegal usage or spread, thanks. 



