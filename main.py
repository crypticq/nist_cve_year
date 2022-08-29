import os
import urllib.request
import gzip
import sys
import json
import requests

def download_file(year:int) -> list:
    """
    download cves from nist db,
    and save the folder and file by (Year) name

    ex:
    download_file(2016)
    will make a folder with the name of 2016
    within that folder will add year json file.
    and read that json file , itrate over each cve,
    append it to a list

    """


    try:
        os.mkdir(str(year))
    except FileExistsError:
        print('Folder Found skiping.. .')
    path = os.path.abspath('.') + "/" + str(year)

    out_file = str(year) + ".json"


    try:
        # Read the file inside the .gz archive located at url
        with urllib.request.urlopen("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz".format(year)) as response:
            with gzip.GzipFile(fileobj=response) as uncompressed:
                file_content = uncompressed.read()


        # write to file in binary mode 'wb'
        with open(f"{path}/{out_file}", 'wb') as f:
            f.write(file_content)
            data = (file_content.decode())
            j_data = json.loads(data)
            cve = j_data['CVE_Items']
            year_cve = []
            for x,i in enumerate(cve):
                cves = (cve[x]['cve']['CVE_data_meta']['ID'])
                year_cve.append(cves)

            circl = "https://cve.circl.lu/api/cve/"
            for found_cve in year_cve:
                yield {
                    'cveData':requests.get(circl+found_cve , headers={'User-Agent':'Circl_Manne'}).json()
                }

    except Exception as e:
        print(e)
        return 1


if __name__ == '__main__':

    year = sys.argv[1]
    for item in download_file(year):

        with open(f"{year}.json", "a") as f:
            json.dump(item, f , indent=4)

    print('Data are saved in json .')
    # from pprint import pprint
    # pprint(item)
