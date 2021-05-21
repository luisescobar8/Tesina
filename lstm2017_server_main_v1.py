# -*- coding: utf-8 -*-
"""
Created on Mon Sep  7 10:40:31 2020

@author: Marcelo
"""
from flask import Flask, request, abort
from keras.models import load_model
from numpy import load
import pickle, time
import os
import logging
import pandas as pd
logging.basicConfig(level=logging.DEBUG)
import sys
import numpy as np

app = Flask(__name__)
xtest = []
lstmModel = None
totalFlows = 0 # total of flows received
respuestas = {}

columns = [ # flow identifier
		'SWID',
		'Protocol',
		'SrcIP', 
		'SrcPort',
		'DstIP',
		'DstPort',
		"Timestamp"]
class_values = {
    0:"normal",
    1:"slowbody2",
    2:"slowread",
    3:"ddossim",
    4:"goldeneye",
    5:"slowheaders",
    6:"rudy",
    7:"hulk",
    8:"slowloris",
    9:"incomplete"
}

# Modify according to your targets
nsteps = 3   # for memoryless models, n = 1
ip_attacker   = "10.0.0.7"
ip_victim     = "10.0.0.1" 
currentAttack = "incomplete"   # copy from class_values*, needs to be precise
experiment = "_rate_300_conn_8000"
#file1 = "/home/marcelo/Documents/ExperimentsMitigation/eval-"+currentAttack+experiment+".txt"
file1 = "C:/Users/labra/Desktop/lstm/eval"+currentAttack+experiment+".txt"
#modelPath  = "/home/marcelo/Documents/ReactiveSecuritySolution/ids/slow-rate/lstm/"
modelPath  = "C:/Users/labra/Desktop/lstm/"

#f = open(file1,"w+")
#f.write("ipsource, ipdestination,real_label,pred_label,totalFlows\n")
#f.close()
def raw_flow_to_values(flow):
	return [list(flow.values())]

def load_lstm_model():
    global lstmModel, yytest, center, scale, pca
    lstmModel = load_model(modelPath+'LSTM')
    center = load(modelPath+'center.npy')
    scale = load(modelPath+'scale.npy')
    pca = load(modelPath+'pca.npy')
def preprocessing(x_received):
     xn = (x_received-center)/scale
     xpca = (np.resize(xn,(1,len(xn)))).dot(pca)
     return xpca
def addapting(x):
    global xtest, nsteps
    if len(xtest) < nsteps-1:
        xtest.append(x)
        return False
    else:
        xtest.append(x)
        return True



def evaluating(ipsource, ipdestination, sourcePort, dstPort, protocol,timeStamp, pred_label):
    global totalFlows, ip_attacker,ip_victim,currentAttack,file1, respuestas
    totalFlows = totalFlows + 1
    if pred_label != "incomplete": # systems with memory
        real_label = "normal"
        if ipsource == ip_attacker or ipsource == ip_victim: # labeled as an attack
            real_label =  currentAttack
        print("Real: ",real_label,"Predicted: ",pred_label)
        with open(file1,"a") as f:
            f.write(str(ipsource)+','+str(ipdestination)+ ','+str(sourcePort)+ ','+str(dstPort)+ ','+str(protocol)+ ','+str(timeStamp)+','+str(real_label)+','+str(pred_label)+','+str(totalFlows)+'\n')
            
            # ip src,dst,srcport,srcdest
            llave = ipsource + " - " + ipdestination
            respuestas[llave] = str(pred_label)
            #print(respuestas)
    return 0



@app.route("/respond", methods=['GET','POST'])
def respond():
        global repuestas
        return {"data":respuestas},202
        

@app.route("/predict", methods=['GET','POST'])
def test():
	global xtest, lstmModel  
	yyhat = 9                       # incomplete state, if nstep>1, LSTM and GRU
	if request.method == 'POST':
		values = request.json
		df = pd.DataFrame.from_dict(values, orient='index')
		df = df[0]
		ipsource = df['SrcIP']
		sourcePort = df['SrcPort']
		ipdestination = df['DstIP']
		dstPort = df['DstPort']
		protocol = df['Protocol']
		timeStamp = df['Timestamp']     
		df.drop(columns,axis='rows',inplace=True)
		df = df.values.tolist()
		x_pca = preprocessing(np.array(df))
		if addapting(x_pca):
		    xxtest = np.array(xtest)
		    xtest = []
		    xxtest = (np.resize(xxtest,(len(xxtest),15)))
		    xxtest = np.array([xxtest])
		    yyhat = lstmModel.predict(xxtest)
		    yyhat = np.argmax(yyhat)
		    print(class_values[yyhat])
	evaluating(ipsource, ipdestination, sourcePort, dstPort, protocol,timeStamp ,class_values[yyhat])
	return class_values[yyhat],202

if __name__ == "__main__":
	load_lstm_model()
	#app.run(debug=True, host='0.0.0.0', port = 9001)
	app.run(use_reloader=False, debug=True, host='0.0.0.0', port = 9001)
