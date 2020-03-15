#!/usr/bin/python
import requests, json, time, base64
import threading
import datetime

global_lock = threading.Lock()
file_contents = []


def printHash(i,hash):
    #Print the analysed details in the golobal locked file.
    while global_lock.locked():
        continue

    global_lock.acquire()
    line="%s\t%s\t%s"% (hash,i.get('positives'),i.get('md5'))
    file_contents.append(line)
    global_lock.release()
    line="%s \n\tVT %s positives\n\tXF risk %s\n"% (hash,i.get('positives'),i.get('md5'))

def do_work(content,api='default-api'):	
	batchHashes = ''
	count = 0
	for idx,sha256Hash in enumerate(content):
	    batchHashes += sha256Hash+','
	    count += 1
	    if count == 4 or idx == len(content)-1:
	        params = {'apikey': api, 'resource':batchHashes[:-1] }
		response = requests.get(url, params=params)
	        if (type(response.json()).__name__=='dict'):
	            try:
	                printHash(response.json(),sha256Hash)
	            except:
	                continue
	        else:
	            for idx,i in enumerate(response.json()):
	                try:
	                    printHash(i,batchHashes.split(',')[idx])
	                except:
	                    continue
	        count = 0
	        batchHashes = ''
	        if (idx != len(content)-1):
	            time.sleep(20)

if __name__ == '__main__':

#reading the input file
	print "Script started at ", datetime.datetime.now()
	start = time.time()
	

	url = 'https://www.virustotal.com/vtapi/v2/file/report'
	with open('hashes.txt','r') as in_file:
		content=(line.rstrip() for line in in_file)
		content=list(line for line in content if line)

	total_count=len(content)
	batch_1_len = total_count/2
	batch_2_len = total_count - batch_1_len
	batch_1 = content[:batch_1_len]
	batch_2 = content[batch_1_len:]
	print "Spliting Hashs into different buckets for differnt threads"
	print "Thread 1:",len(batch_1),"Thread 2:",len(batch_2)

#define API keys
	
	api=[]
	api.append('API-A')  
	api.append('API-A')  

#define threads
	t1 = threading.Thread(target=do_work,args=(batch_1,api[0]))
	t2 = threading.Thread(target=do_work,args=(batch_2,api[1]))
	t1.start()
	t2.start()
	t1.join();t2.join()
#writing output into file
	with open("sha1_md5_positivecounts.txt", "w") as file:
		file.write("\n".join(file_contents))
        	file.close()
	
	end = time.time()
	print "Writing output in file sha1_md5_positivecounts.txt"
	print "Finished with in ",end - start
	print "Script ended at  ", datetime.datetime.now()

