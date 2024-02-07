## AdroZooDataset CLI

### Overview

This CLI tool provides functionalities to create datasets for machine learning purposes using the AndroZoo dataset. It allows for faster and parallelized operations compared to other methods, facilitating the creation of datasets with static features extracted from APK files.

### Requirements

- Linux operating system
- AndroZooDataset API key
- `latest.csv` file from [AndroZoo](https://androzoo.uni.lu/lists)
- APKTool for decompiling APK files

### Usage

#### Running the Program

To run the program, execute:

$ python main.py


#### Functionality

1. **Finding Viruses and Benign APKs:**
   - Reads the `latest.csv` file and creates lists containing viruses and benign applications.

2. **Downloading APK Files:**
   - Downloads APK files either of benign or malware types.

3. **Decompiling APK Files:**
   - Decompiles downloaded APK files.

4. **Extracting Static Features:**
   - Extracts static features such as intents and permissions from APK files.

5. **Removing Decompiled Directories:**
   - Removes the directories created during the decompilation process.

6. **Setting AndroZooDataset API Key:**
   - Sets the AndroZooDataset API key as an environment variable required for program operation.

7. **Changing Number of Concurrent Downloads:**
   - Allows changing the number of concurrent downloads, with a default of 1 and a maximum of 20.

### Description

This CLI tool aims to streamline the process of creating datasets for machine learning tasks using the AndroZoo dataset by providing efficient and parallelized operations.

