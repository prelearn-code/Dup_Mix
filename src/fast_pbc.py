import ctypes
import os
import sys

# Define default param string for Type A curve.
PARAM_STR = b"""type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1"""

class NativePBC:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = NativePBC()
        return cls._instance

    def __init__(self):
        try:
            wrapper_path = os.path.join(os.path.dirname(__file__), "libfastpbcwrapper.so")
            self.lib_wrapper = ctypes.CDLL(wrapper_path)
            
            self.lib_wrapper.init_fast_pbc.argtypes = []
            self.lib_wrapper.simulate_pairing_apply.argtypes = []
            
            self.lib_wrapper.init_fast_pbc()
            self.is_valid = True

        except Exception as e:
            self.is_valid = False
            print(f"[fast_pbc] Init failed: {e}")

    def simulate_pairing(self):
        if not self.is_valid:
            return
        self.lib_wrapper.simulate_pairing_apply()

def test_native():
    pbc = NativePBC.get_instance()
    if pbc.is_valid:
        print("native pbc pairing setup valid!")
        pbc.simulate_pairing()
        print("native pbc pairing execution successful!")
    else:
        print("native pbc not working.")

if __name__ == "__main__":
    test_native()
