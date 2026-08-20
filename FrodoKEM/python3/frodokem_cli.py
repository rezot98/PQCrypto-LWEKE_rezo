import os
import sys

# Ensure Python can import frodokem from the current directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from frodokem import FrodoKEM
except ImportError:
    print("\n[ERROR] Could not import 'FrodoKEM'. Ensure this script is in the same folder as 'frodokem.py'.")
    sys.exit(1)

# Base directory setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Target folder locations (../../../../test)
TARGET_TEST_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "..", "test"))
DEBUG_VARIABLES_FOLDER = os.path.join(TARGET_TEST_FOLDER, "frodokem_debug_variables")

# Automatically guarantee both directories exist
if not os.path.exists(TARGET_TEST_FOLDER):
    os.makedirs(TARGET_TEST_FOLDER)
if not os.path.exists(DEBUG_VARIABLES_FOLDER):
    os.makedirs(DEBUG_VARIABLES_FOLDER)

# File paths mapped cleanly to their respective destinations
KEYGEN_DEBUG_FILE = os.path.join(DEBUG_VARIABLES_FOLDER, "frodokem_keygen_debug.txt")
ENCAPS_DEBUG_FILE = os.path.join(DEBUG_VARIABLES_FOLDER, "frodokem_encaps_debug.txt")
DECAPS_DEBUG_FILE = os.path.join(DEBUG_VARIABLES_FOLDER, "frodokem_decaps_debug.txt")
ALL_IN_ONE_DEBUG_FILE = os.path.join(DEBUG_VARIABLES_FOLDER, "frodokem_all_in_one_debug.txt")

PK_FILE = os.path.join(TARGET_TEST_FOLDER, "public_key.bin")
SK_FILE = os.path.join(TARGET_TEST_FOLDER, "secret_key.bin")
CT_FILE = os.path.join(TARGET_TEST_FOLDER, "ciphertext.bin")

def select_variant():
    print("\n=== 1. SELECT FRODOKEM SHAKE VARIANT ===")
    print("1) FrodoKEM-640 (SHAKE)")
    print("2) FrodoKEM-976 (SHAKE)")
    print("3) FrodoKEM-1344 (SHAKE)")
    print("4) Reset (Delete all public keys and debug logs)")

    choice = input("Enter choice (1-4): ").strip()

    # Handle the Reset option immediately
    if choice == "4" or choice.lower() == "reset":
        files_to_delete = [
            KEYGEN_DEBUG_FILE, ENCAPS_DEBUG_FILE, DECAPS_DEBUG_FILE, 
            ALL_IN_ONE_DEBUG_FILE, PK_FILE, SK_FILE, CT_FILE
        ]
        deleted_any = False

        print(f"\n--- Running Workspace Reset ---")
        for file_path in files_to_delete:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted: {file_path.replace(TARGET_TEST_FOLDER, 'test')}")
                deleted_any = True

        if not deleted_any:
            print("Workspace was already completely clean. No files to delete.")
        else:
            print("[SUCCESS] All temporary files and debug logs successfully cleared!")

        print("Exiting.")
        sys.exit(0)

    variants = {
        "1": "FrodoKEM-640-SHAKE",
        "2": "FrodoKEM-976-SHAKE",
        "3": "FrodoKEM-1344-SHAKE"
    }

    if choice not in variants:
        print(f"\n[INVALID CHOICE] '{choice}' is not a valid option. Please choose 1, 2, 3, or 4.")
        print("Exiting.")
        sys.exit(1)

    return variants[choice]

def select_operation():
    print("\n=== 2. SELECT OPERATION ===")
    print("1) Key Generation (keygen)")
    print("2) Encapsulation (encaps)")
    print("3) Decapsulation (decaps)")
    print("4) All in once (keygen -> encaps -> decaps)")

    choice = input("Enter choice (1-4): ").strip()

    if choice == "1":
        return "keygen"
    elif choice == "2":
        return "encaps"
    elif choice == "3":
        return "decaps"
    elif choice == "4":
        return "all"
    else:
        print(f"\n[INVALID CHOICE] '{choice}' is not a valid operation choice. Please choose 1, 2, 3, or 4.")
        print("Exiting.")
        sys.exit(1)

def setup_keygen_interceptors(kem):
    with open(KEYGEN_DEBUG_FILE, "w") as f:
        f.write(f"=== FrodoKEM Keygen Debug Dump ({kem.variant}) ===\n\n")

    def custom_print(name, value):
        if name in ["randomness", "pkh"]:
            val_hex = value.hex() if isinstance(value, bytes) else str(value)
            print(f"\n[CONSOLE] {name.upper()}:\n{val_hex}")

        with open(KEYGEN_DEBUG_FILE, "a") as f:
            if isinstance(value, bytes):
                f.write(f"{name}:\n{value.hex()}\n\n")
            elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], list):
                f.write(f"{name} (Matrix):\n")
                for row in value:
                    unsigned_row = [x & 0xFFFF if isinstance(x, int) else x for x in row]
                    f.write(f"  {unsigned_row}\n")
                f.write("\n")
            else:
                f.write(f"{name}:\n{value}\n\n")

    kem._FrodoKEM__print_intermediate_value = custom_print

def setup_encaps_interceptors(kem):
    with open(ENCAPS_DEBUG_FILE, "w") as f:
        f.write(f"=== FrodoKEM Encapsulation Debug Dump ({kem.variant}) ===\n\n")

    def custom_print(name, value):
        norm_name = name.lower()

        if isinstance(value, bytes):
            is_pk = (norm_name == "pk")
            is_u = (norm_name == "u" or norm_name == "mu")
            is_salt = ("salt" in norm_name)
            is_k = (norm_name == "k")
            is_ss = (norm_name == "ss")

            if is_pk or is_u or is_salt or is_k or is_ss:
                label = "INPUT PUBLIC KEY (pk)" if is_pk else \
                        "U (UNIFORMLY RANDOM VALUE u)" if is_u else \
                        "SALT" if is_salt else \
                        "INTERMEDIATE KEY k (Step 3)" if is_k else \
                        "FINAL SHARED SECRET ss (Step 15)"
                print(f"\n[CONSOLE] {label}:\n{value.hex()}")

        with open(ENCAPS_DEBUG_FILE, "a") as f:
            if isinstance(value, bytes):
                f.write(f"{name}:\n{value.hex()}\n\n")
            elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], list):
                f.write(f"{name} (Matrix):\n")
                for row in value:
                    unsigned_row = [x & 0xFFFF if isinstance(x, int) else x for x in row]
                    f.write(f"  {unsigned_row}\n")
                f.write("\n")
            else:
                f.write(f"{name}:\n{value}\n\n")

    kem._FrodoKEM__print_intermediate_value = custom_print

def setup_decaps_interceptors(kem):
    with open(DECAPS_DEBUG_FILE, "w") as f:
        f.write(f"=== FrodoKEM Decapsulation Debug Dump ({kem.variant}) ===\n\n")

    def custom_print(name, value):
        norm_name = name.lower()

        if isinstance(value, bytes):
            is_sk = (norm_name == "sk")
            is_ct = (norm_name == "ct" or norm_name == "c")
            is_k = (norm_name == "k" or norm_name == "k'")
            is_ss = (norm_name == "ss" or norm_name == "ss'")

            if is_sk or is_ct or is_k or is_ss:
                label = "INPUT SECRET KEY (sk)" if is_sk else \
                        "INPUT CIPHERTEXT (ct)" if is_ct else \
                        "INTERMEDIATE RECOVERED KEY k' (Step 11)" if is_k else \
                        "FINAL DECAPSULATED SHARED SECRET ss (Step 18)"
                print(f"\n[CONSOLE] {label}:\n{value.hex()}")

        with open(DECAPS_DEBUG_FILE, "a") as f:
            if isinstance(value, bytes):
                f.write(f"{name}:\n{value.hex()}\n\n")
            elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], list):
                f.write(f"{name} (Matrix):\n")
                for row in value:
                    unsigned_row = [x & 0xFFFF if isinstance(x, int) else x for x in row]
                    f.write(f"  {unsigned_row}\n")
                f.write("\n")
            else:
                f.write(f"{name}:\n{value}\n\n")

    kem._FrodoKEM__print_intermediate_value = custom_print

def run_keygen(kem, io_only=False):
    captured_inputs = {}

    if io_only:
        def custom_print(name, value):
            if name.lower() in ["randomness", "z"]:
                captured_inputs[name] = value.hex() if isinstance(value, bytes) else str(value)
        kem._FrodoKEM__print_intermediate_value = custom_print
        print("\n--- Executing Keygen Matrix Computations ---")
        pk, sk = kem.kem_keygen()
    else:
        with open(KEYGEN_DEBUG_FILE, "w") as f:
            f.truncate(0)
        setup_keygen_interceptors(kem)
        print("\n--- Executing Keygen Matrix Computations ---")
        pk, sk = kem.kem_keygen()

    with open(PK_FILE, "wb") as f:
        f.write(pk)
    with open(SK_FILE, "wb") as f:
        f.write(sk)

    print("--- Keygen Execution Finished ---")
    return pk, sk, captured_inputs

def run_encaps(kem, pk=None, io_only=False):
    captured_inputs = {}

    if pk is None:
        if not os.path.exists(PK_FILE):
            print(f"\n[ERROR] Public key file ('public_key.bin') not found in target folder.")
            sys.exit(1)
        with open(PK_FILE, "rb") as f:
            pk = f.read()

    if io_only:
        def custom_print(name, value):
            norm = name.lower()
            if norm in ["u", "mu"] or "salt" in norm:
                if isinstance(value, bytes):
                    captured_inputs[name] = value.hex()
        kem._FrodoKEM__print_intermediate_value = custom_print

        print("\n--- Executing Encapsulation Matrix Computations ---")
        try:
            ct, ss = kem.kem_encaps(pk)
        except AssertionError as e:
            print(f"\n[ERROR] Matrix processing halted due to variant parameter conflict: {e}")
            sys.exit(1)
    else:
        with open(ENCAPS_DEBUG_FILE, "w") as f:
            f.truncate(0)

        setup_encaps_interceptors(kem)
        print("\n--- Executing Encapsulation Matrix Computations ---")
        kem._FrodoKEM__print_intermediate_value("pk", pk)

        try:
            ct, ss = kem.kem_encaps(pk)
        except AssertionError as e:
            print(f"\n[ERROR] Matrix processing halted due to variant parameter conflict: {e}")
            sys.exit(1)

    with open(CT_FILE, "wb") as f:
        f.write(ct)

    print(f"\n[CONSOLE] FINAL SHARED SECRET ss:\n{ss.hex()}")
    print(f"\n[CONSOLE] CIPHERTEXT (ct):\n{ct.hex()}")
    print("--- Encapsulation Execution Finished ---")
    return ct, ss, captured_inputs

def run_decaps(kem, sk=None, ct=None, io_only=False):
    if sk is None:
        if not os.path.exists(SK_FILE):
            print(f"\n[ERROR] Secret key file ('secret_key.bin') not found in target folder.")
            sys.exit(1)
        with open(SK_FILE, "rb") as f:
            sk = f.read()

    if ct is None:
        if not os.path.exists(CT_FILE):
            print(f"\n[ERROR] Ciphertext file ('ciphertext.bin') not found in target folder.")
            sys.exit(1)
        with open(CT_FILE, "rb") as f:
            ct = f.read()

    if io_only:
        kem._FrodoKEM__print_intermediate_value = lambda name, value: None
        print("\n--- Executing Decapsulation Matrix Computations ---")
        try:
            ss = kem.kem_decaps(sk, ct)
        except AssertionError as e:
            print(f"\n[ERROR] Matrix processing halted due to variant parameter conflict: {e}")
            sys.exit(1)
    else:
        with open(DECAPS_DEBUG_FILE, "w") as f:
            f.truncate(0)

        setup_decaps_interceptors(kem)
        print("\n--- Executing Decapsulation Matrix Computations ---")

        kem._FrodoKEM__print_intermediate_value("sk", sk)
        kem._FrodoKEM__print_intermediate_value("ct", ct)

        try:
            ss = kem.kem_decaps(sk, ct)
        except AssertionError as e:
            print(f"\n[ERROR] Matrix processing halted due to variant parameter conflict: {e}")
            sys.exit(1)

    print(f"\n[CONSOLE] FINAL DECAPSULATED SHARED SECRET ss:\n{ss.hex()}")
    print("--- Decapsulation Execution Finished ---")
    return ss

def main():
    # 1. Choose variant or Reset
    variant = select_variant()
    kem = FrodoKEM(variant)
    print(f"\nInitialized configuration: {variant}")

    # 2. Choose operation
    operation = select_operation()

    if operation == "keygen":
        run_keygen(kem, io_only=False)
        print(f"[SUCCESS] Debug log generated: test/frodokem_debug_variables/{os.path.basename(KEYGEN_DEBUG_FILE)}")
    elif operation == "encaps":
        run_encaps(kem, io_only=False)
        print(f"[SUCCESS] Debug log generated: test/frodokem_debug_variables/{os.path.basename(ENCAPS_DEBUG_FILE)}")
    elif operation == "decaps":
        run_decaps(kem, io_only=False)
        print(f"[SUCCESS] Debug log generated: test/frodokem_debug_variables/{os.path.basename(DECAPS_DEBUG_FILE)}")
    elif operation == "all":
        print("\n==================================================")
        print("    STARTING ALL-IN-ONE FULL KEM FLOW PIPELINE   ")
        print("==================================================")
        
        # 1. Keygen
        pk, sk, keygen_inputs = run_keygen(kem, io_only=True)
        
        # 2. Encaps
        ct, encaps_ss, encaps_inputs = run_encaps(kem, pk, io_only=True)
        
        # 3. Decaps
        decaps_ss = run_decaps(kem, sk, ct, io_only=True)

        # Write ALL I/O vectors to a SINGLE text file
        with open(ALL_IN_ONE_DEBUG_FILE, "w") as f:
            f.write(f"=== FrodoKEM All-in-One I/O Summary ({variant}) ===\n\n")
            
            # --- Keygen Block ---
            f.write("--- 1. KEY GENERATION ---\n")
            for k, v in keygen_inputs.items():
                f.write(f"INPUT SEED/RANDOMNESS ({k}):\n{v}\n\n")
            f.write(f"OUTPUT PUBLIC KEY (pk):\n{pk.hex()}\n\n")
            f.write(f"OUTPUT SECRET KEY (sk):\n{sk.hex()}\n\n")
            
            # --- Encaps Block ---
            f.write("--- 2. ENCAPSULATION ---\n")
            f.write(f"INPUT PUBLIC KEY (pk):\n{pk.hex()}\n\n")
            for k, v in encaps_inputs.items():
                f.write(f"INPUT SEED/RANDOMNESS ({k}):\n{v}\n\n")
            f.write(f"OUTPUT CIPHERTEXT (ct):\n{ct.hex()}\n\n")
            f.write(f"OUTPUT SHARED SECRET (ss):\n{encaps_ss.hex()}\n\n")
            
            # --- Decaps Block ---
            f.write("--- 3. DECAPSULATION ---\n")
            f.write(f"INPUT SECRET KEY (sk):\n{sk.hex()}\n\n")
            f.write(f"INPUT CIPHERTEXT (ct):\n{ct.hex()}\n\n")
            f.write(f"OUTPUT SHARED SECRET (ss):\n{decaps_ss.hex()}\n\n")
            
            # --- Verification Result ---
            f.write("--- 4. VERIFICATION RESULT ---\n")
            match_status = "PASSED (Shared secrets match)" if encaps_ss == decaps_ss else "FAILED (Shared secrets mismatch)"
            f.write(f"STATUS: {match_status}\n")

        print("\n==================================================")
        if encaps_ss == decaps_ss:
            print("[VERIFICATION PASSED] Shared secrets MATCH successfully!")
            print(f"Shared Secret: {encaps_ss.hex()}")
        else:
            print("[VERIFICATION FAILED] Encapsulated and Decapsulated shared secrets DO NOT MATCH!")
        print("==================================================")
        print(f"[SUCCESS] Combined I/O log generated: test/frodokem_debug_variables/{os.path.basename(ALL_IN_ONE_DEBUG_FILE)}")

    print("\nExecution finished. Exiting.")

if __name__ == '__main__':
    main()