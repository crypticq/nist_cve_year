import os
import urllib.request
import gzip
import sys
import json
import requests
import concurrent.futures




def download_file(year:int) -> dict:
    """
    download cves from nist db,
    and save the folder and file by (Year) name

    ex:
    download_file(2016)
    will make a folder with the name of 2016
    within that folder will add year json file.
    return file path , folder path
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
                ff = os.path.join(path,out_file)
                with open(ff, 'wb') as f:
                    f.write(file_content)
            print("Done downloading feed from nist")
            return {'full_path':os.path.join(path,out_file), 'just_path':path}
 

    except Exception as e:
        print(e)
        return 1




all_cve = []

circl_data = []


def circl_cve(cve):

     r = requests.get(f"https://cve.circl.lu/api/cve/{cve}")
     if r.status_code == 200:
         print("Adding cve %s data " % cve)
         circl_data.append(r.json())




if __name__ == '__main__':
    year = sys.argv[1]
    ff = download_file(year)
    with open(ff['full_path']) as data:
        j_data = json.load(data)

    cve = j_data['CVE_Items']
    for x, i in enumerate(cve):
        cves = (cve[x]['cve']['CVE_data_meta']['ID'])
        all_cve.append(cves)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        pool.map(circl_cve , all_cve)
    folder = ff['just_path']
    with open(f"{folder}/cricl_{year}.json", "a") as f:
        json.dump(circl_data, f)

