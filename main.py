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

class PrepareApksGCLI:
    def __init__(self):
        self.main_input()

    def main_input(self):
        while True:
            print('1.Find viruses or benign apks from latest.csv file.')
            print('2.Download apk files.')
            print('3.Decompile apk files.')
            print('4.Extract static features from apk files.')
            print('5.Remove decompiled dirs.')
            print('6.Quit')
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
                    return 0
            except ValueError:
                print('You entered the wrong number, please try again!')
    
    def remove_dirs(self):
        removing_dir = simpledialog.askstring("Directory to delete decompiled folders", "Enter benign or malware: ", parent=self.master)
        if removing_dir:
            folder_manager = FolderManager(tool_directory=os.getcwd(), base_path=removing_dir)
            folder_manager.delete_unused_decompiled_folders()
        self.show_notification(f'Decompiled dirs has been removed!')

    def enter_api_key(self):
        api_key = simpledialog.askstring("API KEY", "Enter correct api key:", parent=self.master)

        os.environ["ZooDataSet"] = api_key

        self.show_notification(f"Your env variable has been set: {os.environ['ZooDataSet']}")
    
   

    def change_workers(self):
        self.concurrent_downloads =  int(simpledialog.askstring("Concurrent downloads", "Enter int number (max 20):", parent=self.master))
        self.show_notification(f"Your concurrent downloads has been changed to {self.concurrent_downloads} !")
        
    def extract_features(self):
        dir_to_extract_features_from = simpledialog.askstring("Directory for features extraction", "Enter 'malware' or 'benign':", parent=self.master)
        manifest_processor = ManifestProcessor(
            tool_directory=os.getcwd(),
            manifests_directory="manifests",
            extracted_csv='found_features_verified_all.csv',
            extraction_dir=dir_to_extract_features_from
        )

        manifest_processor.process_manifests()
        self.show_notification("Static features has been extracted!")

    def ask_download_type(self):
        download_type = simpledialog.askstring("Download Type", "Enter 'malware' or 'benign':", parent=self.master)
        if download_type:
            self.download_files(download_type.lower())
    
    def ask_dir_decompile(self):
        decompile_dir = simpledialog.askstring("Directory to decompile", "Enter benign or malware: ", parent=self.master)
        if decompile_dir:
            self.decompile_apks(decompile_dir.lower())
    

    def download_files(self, download_type):

        apk_downloader = APKDownloader(
            api_key=os.environ['ZooDataSet'],
            concurrent_downloads=self.concurrent_downloads,
            tool_directory=os.getcwd()
        )

        def update_progress(progress):
            print(f"Progress: {progress:.2f}%")
            if progress % 5 == 0:
                self.progress_bar["value"] = progress
                self.master.update_idletasks()
        
        apk_downloader.set_progress_callback(update_progress)

        if download_type == 'malware':
            apk_downloader.run(malicious=True, benign=False)
        elif download_type == 'benign':
            apk_downloader.run()
        else:
            print("Invalid download_type. Please enter 'malware' or 'benign'.")
            return

        self.progress_bar.stop()
        self.progress_bar.destroy()

    def find_files(self):
        
        args = parse_arguments_find_files()
        print(args)
        virus_finder = VirusFinder(args.input_csv, args.viruses_txt, args.benign_txt)

        def update_progress(progress):
            print(f"Progress: {progress:.2f}%")
            
        virus_finder.set_progress_callback(update_progress)
        virus_finder.find_viruses()

        

   
    def decompile_apks(self, decompile_dir):
        apk_processor = ApkProcessor(
        tool_directory=os.getcwd(),
        manifests_dir="manifests",
        decompile_dir=decompile_dir,
        decompiled_apks_list="decompiled_apks.txt"
    )
        apk_processor.process()
    

        
if __name__ == "__main__":
     apk = PrepareApksGCLI()
     