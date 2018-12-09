"""HIPS_8_FW_XML_Parser_Action - Driver
Develoepd by: Wade, Timothy J.
UPDATED JULY 2014 - v300
UPDATED Nov 14, 2018 Terrence L. Ward - v400
"""

import HBSS_Classes, os, HIPS_8_FW_XML_Parser_Action

hbss_parser = HBSS_Classes.HBSSXMLParser()
xmlfiles = []
print('############################')
print('# UNDER ACTIVE DEVELOPMENT #')
print('############################\n')
print("HBSS XML PARSER - DEVELOPED BY WADE, TIMOTHY J.")
print("This CLI application will create human readable CSV spreadsheets from\n"
      "XML files directly exported from the McAfee ePolicy Orchestrator.")
print("\nSupported products:\n")
for each_entry in hbss_parser.product_dict:
    print(" " + each_entry)
print(" HOSTIPS_8000_FW")
print("\nThe following files will be checked against supported "
      "XML file types:\n")
for each_file in os.listdir():
    if each_file.endswith('.xml'):
        xmlfiles.append(each_file)
        print(each_file)
date_check = input("\nFor HIPS 8 FW Policies only, would you also like to create an additional \n.CSV file containing only new rules created/modified since a given date? \n(For all other policies, enter N): Y/N ")
if (date_check.lower().startswith('y')):
    date_input = input("\nFile will only contain new rules created/modified since\n MM-DD-YYYY? (include hyphens when entering date value): ")
    sincedate = True
else:
    sincedate = False
begin_check = input("\nBegin parsing to CSV? Y/N ")
if (begin_check.lower().startswith('y')):
    hbss_parser.currentDirXMLListBLDR()
    hbss_parser.hbssObjectListBLDR()
    hbss_parser.hbssObjParseToCSV()
    dirfiles = os.listdir()
    for xmlfile in xmlfiles:
        if (xmlfile[:-4] + '_CSV.csv') in dirfiles:
            pass
        else:
            try:
                args = ['HIPS_8_FW_XML_Parser_Action.py', xmlfile]
                HIPS_8_FW_XML_Parser_Action.main(args, True)
                if sincedate:
                    args = ['HIPS_8_FW_XML_Parser_Action.py', xmlfile, date_input]
                    HIPS_8_FW_XML_Parser_Action.main(args, True)
            except:
                pass
    
else:
    pass
