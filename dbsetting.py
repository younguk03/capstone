from flask_app import app, List, db

with app.app_context():
    db.create_all()
    db.session.commit()
# import pickle
#
# with open('filtered_payloads.pkl', 'rb') as f:
#     data = pickle.load(f)
#
# # 타입 확인
# print(f"데이터 타입: {type(data)}")
#
# # 전체 길이 출력
# print(f"총 페이로드 수: {len(data)}")
#
# # 앞부분 몇 개만 출력 (예: 10개)
# print("샘플 페이로드:")
# for i, payload in enumerate(data[:10], 1):
#     print(f"{i}. {payload}")
# 모델을 학습하고 저장하기 (예: xss-model 안에 있던 모델)
import pickle
from sklearn.linear_model import LogisticRegression

# 예시: 모델 학습 (실제 코드에서는 데이터셋을 사용)
model = LogisticRegression()
model.fit([[0], [1]], [0, 1])  # 가상의 데이터

# 저장하기
with open('models/xss_detector.pkl', 'wb') as f:
    pickle.dump(model, f)
