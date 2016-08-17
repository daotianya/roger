# roger

protocol feature
          
          1, m:n , m tcp connection map n streams
          2, multiplexing on stream level
          3, reliable packet transfer
          4, ARQ retransmission for the delayed packet
 
build 

          for windows  
            server: projects/roger/projects/msvc/roger/rserver.sln    
            client: projects/roger/projects/msvc/roger_client/roger.sln  
            please note that if you want to debug cilent in MS IDE, you must set debug parameter first 
            (ip and port in command arguments)
          
          for linux  
            makefile path: projects/roger/projects/linux/makefile
            make example: make build=debug arch=x86_64 roger_server
            make example: make build=debug arch=x86_64 roger_client
            make example: make roger_server
            make example: make roger_client
            
            binary file would be in: projects/roger/projects/build/$(ARCH)
            
            codeblock project file:  
            server: projects/roger/projects/codeblocks/roger/roger.workspace
            
usage

          1, start server
          	./roger_server > /dev/null &
          
          2, start client
          	roger_client roger_server_ip roger_server_listen_port
          
          3, setup proxy on browser side   
          	http proxy address: http://roger_client_ip:8088/proxy.pac   
          	socks5 proxy address: roger_client_ip 12122  

discussion group: QQ(452583496)



This is a protocol test project based upon wawo library, we are opposed to any violence and illegal usage or spread, thanks. 



