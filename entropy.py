import math
import os
import re

result_array = []

def GetListFiles(PathForAnalyze):
    ListFiles = []
    for file in os.listdir(PathForAnalyze):
        path = os.path.join(PathForAnalyze, file)
        if os.path.isfile(path):
            if re.findall('[^ ]+\.php',path):
                ListFiles.append(path)
        else:
            ListFiles +=GetListFiles(path)
    return ListFiles

def calc_entropy(inputFileName):
    fileSize = os.path.getsize(inputFileName)
    f = open(inputFileName, 'rb')
    byteArr = bytearray(f.read(fileSize))
    f.close()
    fileSize = len(byteArr)
    strLen = fileSize * 8
    result_entropy = 0.0
    for i in range(5):
        bitLen = 2 ** i
        freqLen = 2 ** bitLen
        freqList = [0] * freqLen
        numSym = int(strLen / bitLen)
        for j in range(numSym):
            sym = ''
            for k in range(bitLen):
                bitInd = bitLen * j + k
                byteInd = int(bitInd / 8)
                if byteInd < fileSize:
                    byteVal = byteArr[byteInd]
                else:
                    byteVal = 0
                bitInByteInd = 7 - bitInd % 8
                bitVal = int(byteVal / 2 ** bitInByteInd) % 2
                sym += str(bitVal)
            freqList[int(sym, 2)] += 1
        for m in range(freqLen):
            try:
                freqList[m] = float(freqList[m]) / numSym
            except ZeroDivisionError:
                pass
        ent = 0.0
        ctr = 0
        for freq in freqList:
            if freq > 0:
                ent = ent + freq * math.log(freq, 2)
                ctr += 1
        ent = -ent
        result_entropy += ent
    result_entropy = result_entropy / 5
    if result_entropy > 4.0:
        print("scan File : {0}".format(inputFileName))
        print("entropy in file - {0}".format(result_entropy))
        print()

def GetReport(PathForScan):
    for i in GetListFiles(PathForScan):
        result_array.append(calc_entropy(i))
