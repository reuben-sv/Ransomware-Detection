Guide to Get the Project Up and Running

1. Download the required datasets:
    EMBER dataset
    BODMAS dataset

2. Place the datasets in the following directory structure:
    database/
    ├── bodmas/
    │   └── bodmas.npz
    └── ember2018/
        ├── train_features_0.jsonl
        ├── train_features_1.jsonl
        ├── train_features_2.jsonl
        ├── train_features_3.jsonl
        ├── train_features_4.jsonl
        └── train_features_5.jsonl

3. Create the training datasets:
    Run create_dynamic_train_set.py and create_static_train_set.py (located inside train_set_creators folder)

4. Verify generated datasets:
    That should have created database\ember_static_features.csv and database\bodmas_dynamic_features.npz (might take a lot of time)

5. Train the models:
    Run train_static_model.py and train_dynamic_model.py (located inside model_trainer folder)

6. Verify trained models:
    That should have created models\Static_Model.pkl and models\Dynamic_Model.pkl

7. Run the detection system:
    Run main.py to perform static and dynamic analysis
    You can add any .exe files you want to the test_executable_files folder for testing.
    Sample1.exe is just a simple python script that doesnt do anything
    Sample2.exe is the READEST softwares setup file


8. Demonstration of ransomware detection:
    Run static_analysis_safe_ransomware.py to showcase static analysis for known ransomware static features

Note:
The file database/malware_rows.csv was created to safely demonstrate how the system identifies ransomware without introducing any risk to the executing machine.
In a real-world deployment, this system should be run inside an isolated sandbox or virtual machine to safely perform dynamic analysis.
The script static_analysis_safe_ransomware.py performs static analysis on three known samples stored in malware_rows.csv and explains the reasoning behind each classification.
This script should not be used in production, as exposing model reasoning could allow ransomware authors to modify their malware to bypass detection.