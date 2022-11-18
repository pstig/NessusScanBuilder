from array import array
import openpyxl
import argparse
import os
from openpyxl import load_workbook
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
import pandas

#Reads files from the scans folder and creates a dataframe from the scans
def createDataSet():
    filenames = []
    data = []
    for x in os.scandir(path='./scans'):
        if os.DirEntry.is_file(x) == True:
            filenames.append(x.name)
    for x in filenames:
        data.append(pandas.read_csv("./scans/" + x))
    results = pandas.concat(data)
    return results

#Uses dataframe 'results' to create an open port matrix

def generatePortMatrix(results):
    test = []
    hostList = results.groupby(['Host'])[['Port']].agg(lambda x: set(x))
    for rows in hostList['Port']:
        for x in rows:
            test.append(x)
    x = pandas.Series(pandas.unique(test), name = 'Port').sort_values().to_list()
    counter = 0
    portMatrix = pandas.DataFrame()
    for row in hostList.index:
        temp = pandas.DataFrame(data= 'X', index=[row], columns=hostList['Port'].values[counter])
        portMatrix = pandas.concat([portMatrix, temp], join='outer')
        counter += 1
    portMatrix.sort_index(axis=1, inplace=True)

    return portMatrix

def generateVulnDetails(results):
    sevMap = pandas.DataFrame({'Risk': ['Low', 'Medium', 'High', 'Critical']})
    sortsevMap = sevMap.reset_index().set_index('Risk')
    results['Remediation'] = results['Solution'] + '\n' + results['See Also']
    results['Risk Num'] = results['Risk'].map(sortsevMap['index'])
    none = 'None'
    op1 = results.query('Risk != @none')
    op1 = op1.reindex(columns=["Host", "Risk", "Port", "Protocol", "Name", "Description", "Remediation", "Plugin Output", "CVE", "Plugin ID", "Synopsis", "Risk Num"])
    op1 = op1.rename(columns={"Host" : "IP", "Name": "Vulnerability", "Plugin Output" : "Output"})
    op1 = op1.sort_values(by=['Risk Num'], ascending=False)
    op1 = op1.drop(['Plugin ID', 'Synopsis', 'Risk Num'], axis=1)
    return op1

#TODO Still has dupes 
def generateGrouped(results):
    sevMap = pandas.DataFrame({'Risk': ['Low', 'Medium', 'High', 'Critical']})
    sortsevMap = sevMap.reset_index().set_index('Risk')
    results['Remediation'] = results['Solution'] + '\n' + results['See Also']
    results['Risk Num'] = results['Risk'].map(sortsevMap['index'])
    none = 'None'
    op1 = results.query('Risk != @none', inplace=False)
    group = op1.groupby(by=['Plugin ID', 'Risk', 'Synopsis', 'Description', 'Remediation', 'Risk Num'], dropna=False)[['Host']].agg(lambda x: x)
    group.sort_values(by=['Risk Num'], ascending=False, inplace=True)
    return group

#TODO fix appending IPs in grouped
#I think the type needs to be changed in the dataframe for Hosts. it seems ws.append() doesnt know how to handle lists
def createReport(portM, vuln, group):
    wb = load_workbook("int.xltx")
    wb.template=False
    wb.active=wb['Open Port Matrix']
    ws = wb.active
    for r in dataframe_to_rows(portM, index=True, header=True):
        ws.append(r)
    wb.active=wb['Vulnerability Details']
    ws = wb.active
    for r in dataframe_to_rows(vuln, index=True, header=True):
        ws.append(r)
    wb.active=wb['Vulnerability Scan - Grouped']
    # for r in dataframe_to_rows(group, index=True, header=True):
    #     ws.append(r)

    wb.save('Sample Internal scan report.xlsx')

#TODO add cmdline controls
#TODO currently hard coded to internal reports
if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description='Create Scan reports from nessus files')
    # parser.add_argument('-t', help='Scan Report type')
    # parser.add_argument('-c', help ='Company')
    # parser.add_argument('-d', help='date of scan')
    # parser.parse_args()

    scanData = createDataSet()
    openPortMatrixDF = generatePortMatrix(scanData)
    vulnDetailsDF = generateVulnDetails(scanData)
    groupedVulnDF = generateGrouped(scanData)
    createReport(openPortMatrixDF, vulnDetailsDF, groupedVulnDF)




