import os

# Import cyclonedx_sbom_gen module
import cyclonedx_sbom_gen

currentPath = os.getcwd()
OUTPUT_DIR = currentPath + "/output"
TARGET_BIN_DIR = currentPath + "/testset/bin"


def generate_sbom(bin_name: str):
    binary_path = os.path.join(TARGET_BIN_DIR, bin_name)
    components_path = os.path.join(OUTPUT_DIR, bin_name, f"{bin_name}.components.json")

    # Check if components file exists
    if not os.path.exists(components_path):
        print(f"    [!] Components file not found: {components_path}")
        return

    # Call cyclonedx_sbom_gen.main with arguments
    print(f"    [*] Generating CycloneDX SBOM for {bin_name}...")
    args = [binary_path, components_path, "--ldd"]
    cyclonedx_sbom_gen.main(args)

    # Print generated SBOM content
    sbom_path = os.path.join(OUTPUT_DIR, f"{bin_name}-sbom.json")
    if os.path.exists(sbom_path):
        print(f"\n{'='*60}")
        print(f"   {bin_name} SBOM")
        print(f"{'='*60}")
        with open(sbom_path, "r", encoding="utf-8") as f:
            sbom_content = f.read()
        print(sbom_content)
        print(f"{'='*60}\n")


def main():
    # detector.py already ran component detection and wrote
    # output/{bin_name}/{bin_name}.components.json per binary; just build the SBOMs.
    for filename in sorted(os.listdir(TARGET_BIN_DIR)):
        filepath = os.path.join(TARGET_BIN_DIR, filename)
        if not os.path.isfile(filepath):
            continue
        bin_name = filename
        print(f"[*] Generating SBOM for binary: {bin_name}")
        generate_sbom(bin_name)


if __name__ == "__main__":
    main()
