# -*- coding: utf-8 -*-
"""
Created on Tue Apr 07 14:08:15 2015

@author: binta
"""

import pylab as pl
from pylab import *  
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

  
ymajorLocator   = MultipleLocator(0.004) #将y轴主刻度标签设置为0.5的倍数  
ymajorFormatter = FormatStrFormatter('%1.3f') #设置y轴标签文本的格式  
yminorLocator   = MultipleLocator(0.002) #将此y轴次刻度标签设置为0.1的倍数  

def read_benchmark(s_ben, i, j):

    time = {}
    count = {}    
    
    f = open(s_ben, 'r')
    line = f.readline()
    while line != '':
        tmp = line.split()
        if tmp[i] != '0':
            time[tmp[i]] = time.get(tmp[i], 0.0) + float(tmp[j])
            count[tmp[i]] = count.get(tmp[i], 0) + 1
        line = f.readline()
    
    for i in time:
        time[i] = time[i] / count[i] 
    return time

def read_sophos(s_ben, i, j):

    time = {}
    count = {}    
    
    f = open(s_ben, 'r')
    line = f.readline()
    while line != '':
        tmp = line.split()
        if tmp[i] != '0':
            time[tmp[i]] = time.get(tmp[i], 0.0) + float(tmp[j])
            count[tmp[i]] = count.get(tmp[i], 0) + 1
        line = f.readline()
    
    for t in time:
        time[t] = time[t] / count[t]
    return time


search_rate = [0.0001, 0.001, 0.01]
style = ['+', '*', '.']
#font = FontProperties(fname=r"c:\windows\fonts\simsun.ttc", size=14) 
pl.figure(figsize=(10,8))

style = ['k^-','r+-', 'b.-' ]
#===============================================
time = read_benchmark('benchmark_discog_client.out', 0, 1)
print "fast:", time
x = [ '10', '100', '1000', '10000', '100000']
y = [time[key] for key in x]

x = [1, 2, 3, 4, 5]
#y = [log10(i) for i in y]

  
pl.plot(x, y, style[0], linewidth=1.9, markersize=13, label="FAST")# use pylab to plot x and y

#===============================================
time = read_benchmark('benchmark_discog_client.out', 0, 1)
print "fastio", time
#time['10000'] = 0.006664441828932286
x = ['10', '100', '1000', '10000', '100000']
y = [time[key] for key in x]

x = [1, 2, 3, 4, 5]
#y = [log10(i) for i in y]
 
pl.plot(x, y, style[1], linewidth=1.9, markersize=12, label="FASTIO")# use pylab to plot x and y


group_labels = ['10', '100','1000','10000','100000']  
pl.xticks(x, group_labels, rotation=0)



##===============================================
time = read_benchmark('benchmark_discog_client.out', 0, 1)
print "sophos", time
#time['10000'] = 0.006664441828932286
#time['100000'] = 0.006774441828932286

x = ['10', '100', '1000', '10000', '100000']
y = [time[key] for key in x]

x = [1, 2, 3, 4, 5]
#y = [log10(i) for i in y]
 
pl.plot(x, y, style[2], markersize=20, linewidth=1.9, label="Sophos")# use pylab to plot x and y

group_labels = ['10', '100','1000','10000','100000']  
pl.xticks(x, group_labels, rotation=0)


#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&

matplotlib.rc('xtick', labelsize=21) 
matplotlib.rc('ytick', labelsize=21)
font = {'family' : 'normal',
 'weight' : 'normal',
 'size' : 16}
matplotlib.rc('font', **font)

pl.legend(loc='upper right')
pl.xlabel('Number of matching documents(log scala)', fontsize=22)
pl.ylabel('Search time per matching entry(ms)', fontsize=22)
#pl.title()
#pl.axis([0.8,5.2,0.0,0.025])


ax = subplot(111)
ax.yaxis.set_major_locator(ymajorLocator)  
ax.yaxis.set_major_formatter(ymajorFormatter) 

ax.yaxis.set_minor_locator(yminorLocator)  

ax.xaxis.grid(True, which='major') #x坐标轴的网格使用主刻度  
ax.yaxis.grid(True, which='minor') #y坐标轴的网格使用次刻度 

pl.rc('grid', linestyle="-.", color='black')
pl.axis([0.8,5.2,0.0,0.025])
#pl.title('|DB|=14e6')

pl.show()# show the plot on the screen

