#!/usr/bin/python3.4
import subprocess
cmd="ext9.c"
subprocess.call(["gcc", cmd,"-lpcap"])
subprocess.call("./a.out test.pcap",shell=True)
print("Do you want to apply filter?[Y/N]")
a=input()
if(a=='y' or a=='Y'):
  print("APPLYING FILTERS")
  choice=input("Apply filter for 1.TCP 2.UDP:")
  fd=open("result.txt","r")
  line = fd.readline()
  while line :
    if choice==1:
      if 'TCP' in line:
        print(line)
        for i in range(0,4):
          line = fd.readline()
          print(line)
      else:
        pass

    if choice==2:
      if 'UDP' in line:
        print(line)
        for i in range(0,3):
          line = fd.readline()
          print(line)
      else:
        pass
    line = fd.readline()
else:
  pass
  fd.close()                              
