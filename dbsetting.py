import gzip
import pickle

with open('models/xss_detector.pkl','rb') as f_in:
    with gzip.open('models/xss_detector.gz', 'wb') as f_out:
        f_out.write(f_in.read())
