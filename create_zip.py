import zipfile
import os

def create_zip():
    files_to_zip = [
        "app.py",
        "utils.py",
        "feature_extractor.py",
        "requirements.txt",
        "test_local.py",
        "start.sh",
        "start.bat",
        "README.md"
    ]
    
    zip_filename = "NIDS_Vanguard.zip"
    
    print(f"Creating {zip_filename}...")
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        for file in files_to_zip:
            if os.path.exists(file):
                zipf.write(file)
                print(f"Added {file}")
            else:
                print(f"Warning: {file} not found.")
                
    print(f"Successfully created {zip_filename}")

if __name__ == "__main__":
    create_zip()
