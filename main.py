import argparse
import os
import subprocess
import sys
import time

from download_apks import APKDownloader
from find_viruses_csv import VirusFinder, parse_arguments_find_files
from decompile import *
from remove_decompiled_dirs import FolderManager
from extract_features import ManifestProcessor
#from dnn import HyperparameterGridSearch

class PrepareApksCLI:
    def __init__(self):
        self.concurrent_downloads = 1
        self.main_input()

    def main_input(self):
        while True:
            print('1.Find viruses or benign apks from latest.csv file.')
            print('2.Download apk files.')
            print('3.Decompile apk files.')
            print('4.Extract static features from apk files.')
            print('5.Remove decompiled dirs.')
            print('6.Set AdroZooDataset Api key to be able to download.')
            print('7.Change number of concurrent downloads (default 1 max 20).')
            print('8.Quit')
            try:
                self.choice = int(input('Enter a number: '))
                if self.choice == 1:
                    self.find_files()
                elif self.choice == 2:
                    self.download_files()
                elif self.choice == 3:
                    self.decompile_apks()
                elif self.choice == 4:
                    self.extract_features()
                elif self.choice == 5:
                    self.remove_dirs()
                elif self.choice == 6:
                    self.enter_api_key()
                elif self.choice == 7:
                    self.change_workers()
                elif self.choice == 8:
                    return 0
            except ValueError:
                print('You entered the wrong number, please try again!')
    
    def remove_dirs(self):
        removing_dir = input("Directory to delete decompiled folders. Enter benign or malware: ")
        if removing_dir:
            folder_manager = FolderManager(tool_directory=os.getcwd(), base_path=removing_dir)
            folder_manager.delete_unused_decompiled_folders()
        print(f'Decompiled dirs has been removed!')

    def enter_api_key(self):
        api_key = input("Enter correct api key: ")
        os.environ["ZooDataSet"] = api_key
        print(f"Your env variable has been set: {os.environ['ZooDataSet']} \n \n")
       
    
    def change_workers(self):
        try:
            self.concurrent_downloads =  int(input("Enter number of concurrent downloads: "))
            print("Number of concurrent downloads has been changed!")
        except ValueError:
                print('You entered the wrong number, please try again!')
        
    def extract_features(self):
        dir_to_extract_features_from = input("Directory for features extraction. Enter 'malware' or 'benign':")
        manifest_processor = ManifestProcessor(
            tool_directory=os.getcwd(),
            manifests_directory="manifests",
            extracted_csv='found_features_verified_all.csv',
            extraction_dir=dir_to_extract_features_from
        )

        manifest_processor.process_manifests()
        


    def download_files(self):

        apk_downloader = APKDownloader(
            api_key=os.environ['ZooDataSet'],
            concurrent_downloads=self.concurrent_downloads,
            tool_directory=os.getcwd()
        )

        def update_progress(progress):
            if progress % 1 == 0:
                print(f"Progress: {progress:.2f}%")
        
        apk_downloader.set_progress_callback(update_progress)

        download_type = input("Enter download type 'malware' or 'benign': ")

        if download_type == 'malware':
            apk_downloader.run(malicious=True, benign=False)
        elif download_type == 'benign':
            apk_downloader.run()
        else:
            print("Invalid download_type. Please enter 'malware' or 'benign'.")
            return

    def find_files(self):
        args = parse_arguments_find_files()
        virus_finder = VirusFinder(args.input_csv, args.viruses_txt, args.benign_txt)
        def update_progress(progress):
            if progress % 1 == 0:
                print(f"Progress: {progress:.2f}%")
        virus_finder.set_progress_callback(update_progress)
        virus_finder.find_viruses()

    def decompile_apks(self):
        decompile_dir = input("Enter which types of files u want to decompile benign or malware: ")
        apk_processor = ApkProcessor(
        tool_directory=os.getcwd(),
        manifests_dir="manifests",
        decompile_dir=decompile_dir,
        decompiled_apks_list="decompiled_apks.txt"
    )
        apk_processor.process()
    

        
if __name__ == "__main__":
     apk = PrepareApksCLI()
     