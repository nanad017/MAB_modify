import torch
import time
import requests
import torch.nn.functional as F
import lightgbm as lgb
import numpy as np
import subprocess
import json
from ember import predict_sample
from MalConv import MalConv
import sys
import joblib
from pathlib import Path
import math
import pefile
"""
sys.path.append('/root/Malware-Detection-System')
try:
    from detect_binary_fi import extract_static_features
except ImportError:
    print('WARNING: could not import extract_static_features from detect_binary_fi.')
"""
def _safe_ratio(numer, denom):
    return float(numer / denom) if denom > 0 else 0.0
class CustomXGBoostModel(object):
    def __init__(self, model_path, thresh=0.5):
        self.model = joblib.load(model_path)
        self.thresh = thresh
        self.__name__ = 'xgboost'

    def get_score(self, file_path):
        features = extract_static_features(Path(file_path)).reshape(1, -1)
        score = self.model.predict_proba(features)[0,1]
        return score

    def is_evasive(self, file_path):
        score = self.get_score(file_path)
        return score < self.thresh

class RemoteDetectorModel(object):
    def __init__(self, url, thresh=0.5, shared_root='/root/MAB-malware/data/share', name='remote_detector'):
        self.url = url
        self.thresh = thresh
        self.shared_root = Path(shared_root).resolve()
        self.__name__ = name

    def get_score(self, file_path):
        try:
            file_path = Path(file_path).resolve()
            relative_path = str(file_path.relative_to(self.shared_root))

            response = requests.post(
                self.url,
                json={'relative_path': relative_path},
                timeout=30,
            )
            response.raise_for_status()
            result = response.json()
            return float(result['score'])
        except Exception as e:
            print(f"RemoteDetectorModel error: {e}")
            return 1.0

    def is_evasive(self, file_path):
        score = self.get_score(file_path)
        return score < self.thresh
class MalConvModel(object):
    def __init__(self, model_path, thresh=0.5, name='malconv'): 
        self.model = MalConv(channels=256, window_size=512, embd_size=8).train()
        weights = torch.load(model_path,map_location='cpu')
        self.model.load_state_dict( weights['model_state_dict'])
        self.thresh = thresh
        self.__name__ = name

    def get_score(self, file_path):
        try:
            with open(file_path, 'rb') as fp:
                bytez = fp.read(2000000)        # read the first 2000000 bytes
                _inp = torch.from_numpy( np.frombuffer(bytez,dtype=np.uint8)[np.newaxis,:] )
                with torch.no_grad():
                    outputs = F.softmax( self.model(_inp), dim=-1)
                return outputs.detach().numpy()[0,1]
        except Exception as e:
            print(e)
        return 0.0 
    
    def is_evasive(self, file_path):
        score = self.get_score(file_path)
        #print(os.path.basename(file_path), score)
        return score < self.thresh

#class EmberModel_gym(object):      # model in gym-malware
#    # ember_threshold = 0.8336 # resulting in 1% FPR
#    def __init__(self, model_path, thresh=0.9, name='ember'):       # 0.9 or 0.8336
#        # load lightgbm model
#        self.local_model = joblib.load(model_path)
#        self.thresh = thresh
#        self.__name__ = 'ember'
#
#    def get_score(self, file_path):
#        with open(file_path, 'rb') as fp:
#            bytez = fp.read()
#            #return predict_sample(self.model, bytez) > self.thresh
#            features = feature_extractor.extract( bytez )
#            score = local_model.predict_proba( features.reshape(1,-1) )[0,-1]
#            return score
#    
#    def is_evasive(self, file_path):
#        score = self.get_score(file_path)
#        return score < self.thresh

class EmberModel_2019(object):       # model in MLSEC 2019
    def __init__(self, model_path, thresh=0.8336, name='ember'):
        # load lightgbm model
        self.model = lgb.Booster(model_file=model_path)
        self.thresh = thresh
        self.__name__ = 'ember'

    def get_score(self,file_path):
        with open(file_path, 'rb') as fp:
            bytez = fp.read()
            score = predict_sample(self.model, bytez)
            return score
    
    def is_evasive(self, file_path):
        score = self.get_score(file_path)
        return score < self.thresh

#class EmberModel_2020(object):      # model in MLSEC 2020
#    '''Implements predict(self, bytez)'''
#    def __init__(self,
#                 name: str = 'ember_MLSEC202H0',
#                 thresh=0.8336):
#        self.thresh = thresh
#        self.__name__ = name
#
#    def get_score(self, file_path):
#        with open(file_path, 'rb') as fp:
#            bytez = fp.read()
#            url = 'http://127.0.0.1:8080/'
#            timeout = 5
#            error_msg = None
#            res = None
#            start = time.time()
#            try:
#                res = self.get_raw_result(bytez, url, timeout)
#                score = res.json()['score']
#            except (requests.RequestException, KeyError, json.decoder.JSONDecodeError) as e:
#                score = 1.0  # timeout or other error results in malicious
#                error_msg = str(e)
#                if res:
#                    error_msg += f'-{res.text()}'
#            return score
#    
#    def is_evasive(self, file_path):
#        score = self.get_score(file_path)
#        return score < self.thresh
#    
#    def get_raw_result(self, bytez, url, timeout):
#        return requests.post(url, data=bytez, headers={'Content-Type': 'application/octet-stream'}, timeout=timeout)

class ClamAV(object):
    def is_evasive(self, file_path):
        res = subprocess.run(['clamdscan', '--fdpass', file_path], stdout=subprocess.PIPE)
        #print(res.stdout)
        if 'FOUND' in str(res.stdout):
            return False
        elif 'OK' in str(res.stdout):
            return True
        else:
            print('clamav error')
            exit()
def extract_static_features(path: Path) -> np.ndarray:
    """Extract fixed-size static features from a PE file (271 dims)."""
    bytez = path.read_bytes()
    arr = np.frombuffer(bytez, dtype=np.uint8)
    if arr.size == 0:
        raise ValueError("Empty file")

    hist = np.bincount(arr, minlength=256).astype(np.float32)
    hist /= max(1, arr.size)

    probs = hist[hist > 0]
    printable = ((arr >= 32) & (arr <= 126)).sum()

    raw_stats = np.array(
        [
            math.log1p(arr.size),
            float(arr.mean()),
            float(arr.std()),
            float(arr.min()),
            float(arr.max()),
            _safe_ratio(int((arr == 0).sum()), arr.size),
            _safe_ratio(int(printable), arr.size),
        ],
        dtype=np.float32,
    )

    pe_stats = np.zeros(8, dtype=np.float32)
    try:
        pe = pefile.PE(data=bytez, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])

        sections = pe.sections if pe.sections is not None else []
        sec_entropies = [float(s.get_entropy()) for s in sections]
        sec_raw_sizes = [float(s.SizeOfRawData) for s in sections]
        sec_virt_sizes = [float(s.Misc_VirtualSize) for s in sections]

        import_dlls = 0
        import_funcs = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
            import_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            import_funcs = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)

        pe_stats = np.array(
            [
                float(len(sections)),
                float(np.mean(sec_entropies)) if sec_entropies else 0.0,
                float(np.std(sec_entropies)) if sec_entropies else 0.0,
                float(np.mean(sec_raw_sizes)) if sec_raw_sizes else 0.0,
                float(np.mean(sec_virt_sizes)) if sec_virt_sizes else 0.0,
                float(import_dlls),
                float(import_funcs),
                float(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)),
            ],
            dtype=np.float32,
        )
    except Exception:
        pass

    return np.concatenate([hist, raw_stats, pe_stats]).astype(np.float32)

