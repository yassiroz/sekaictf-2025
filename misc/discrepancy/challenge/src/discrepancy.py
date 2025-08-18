### IMPORTS ###
from pickle import _Unpickler as py_unpickler
from _pickle import Unpickler as c_unpickler
from pickletools import dis
from io import BytesIO
DEBUG = False



### HELPER FUNCTIONS ###
def py_pickle_wrapper(data: bytes) -> bool:
    """
    Wrapper function for Python's pickle.loads.
    """

    class SafePyUnpickler(py_unpickler):
        def find_class(self, module_name: str, global_name: str):
            print("no no no")
            exit(1)

    try:
        SafePyUnpickler(BytesIO(data)).load()
        return True
    except Exception:
        if DEBUG:
            print("Failed SafePyUnpickler")
        return False
    
def c_pickle_wrapper(data: bytes) -> bool:
    """
    Wrapper function for C's pickle.loads.
    """

    class SafeCUnpickler(c_unpickler):
        def find_class(self, module_name: str, global_name: str):
            print("no no no")
            exit(1)

    try:
        SafeCUnpickler(BytesIO(data)).load()
        return True
    except Exception:
        if DEBUG:
            print("Failed SafeCUnpickler")
        return False
    
def pickletools_wrapper(data: bytes) -> bool:
    """
    Wrapper function for pickletools.genops.
    """
    try:
        dis(data)
        return True
    except Exception:
        if DEBUG:
            print("Failed genops")
        return False
    
def get_input() -> bytes:
    inp = input("Pickle bytes in hexadecimal format: ")
    if inp.startswith("0x"):
        inp = inp[2:]

    b = bytes.fromhex(inp)[:8]
    return b



### MAIN ###
if __name__ == "__main__":
    # Check 1
    print("Check 1")
    b1 = get_input()
    if py_pickle_wrapper(b1) and c_pickle_wrapper(b1) and not pickletools_wrapper(b1):
        print("Passed check 1")
    else:
        print("Failed check 1")
        exit(1)

    # Check 2
    print("Check 2")
    b2 = get_input()
    if not py_pickle_wrapper(b2) and c_pickle_wrapper(b2) and pickletools_wrapper(b2):
        print("Passed check 2")
    else:
        print("Failed check 2")
        exit(1)

    # Check 3
    print("Check 3")
    b3 = get_input()
    if py_pickle_wrapper(b3) and not c_pickle_wrapper(b3) and pickletools_wrapper(b3):
        print("Passed check 3")
    else:
        print("Failed check 3")
        exit(1)

    # Check 4
    print("Check 4")
    b4 = get_input()
    if not py_pickle_wrapper(b4) and not c_pickle_wrapper(b4) and pickletools_wrapper(b4):
        print("Passed check 4")
    else:
        print("Failed check 4")
        exit(1)

    # Check 5
    print("Check 5")
    b5 = get_input()
    if not py_pickle_wrapper(b5) and c_pickle_wrapper(b5) and not pickletools_wrapper(b5):
        print("Passed check 5")
    else:
        print("Failed check 5")
        exit(1)

    # get flag
    print("All checks passed")
    FLAG = open("flag.txt", "r").read()
    print(FLAG)
