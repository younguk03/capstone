import pickle
import gzip

# 1. 기존 압축 안 된 pkl 파일 읽기
with open('./models/xss_detector.pkl', 'rb') as f:
    obj = f.read(2)
    print(obj)


# 2. 압축된 pkl.gz 파일로 저장
# with gzip.open('./models/xss_detector.gz', 'wb') as f_out:
#     pickle.dump(obj, f_out)

