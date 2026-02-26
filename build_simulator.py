import os

def create_clean_build():
    content = "SAFE_APPLICATION_CODE\n"
    content += "LibraryA\n"
    content += "LibraryB\n"

    with open("dataset/clean/build_clean.txt", "w") as f:
        f.write(content)

def create_compromised_build():
    content = "SAFE_APPLICATION_CODE\n"
    content += "LibraryA\n"
    content += "LibraryB\n"
    content += "MALICIOUS_BACKDOOR\n"

    with open("dataset/compromised/build_compromised.txt", "w") as f:
        f.write(content)

if __name__ == "__main__":
    create_clean_build()
    create_compromised_build()
    print("Build artifacts generated successfully.")