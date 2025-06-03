import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

# ===== vectorize_input 임시 정의 (길이 기반 피처) =====
def vectorize_input(url, param, value):
    return [
        len(url),
        len(param),
        len(value),
        value.count("'") + value.count('"'),
        sum(1 for c in value if not c.isalnum())
    ]

# ========== 🔹 SQLi 모델 학습 및 저장 ==========

SQLI_DATA_PATH = os.path.join(os.getcwd(), 'data', 'sqli_dataset.csv')
if os.path.exists(SQLI_DATA_PATH):
    print("📥 SQLi 데이터 로드 중...")
    data = pd.read_csv(SQLI_DATA_PATH)

    X = data.apply(lambda r: vectorize_input(r['url'], r['param'], r['value']), axis=1).tolist()
    y = data['label'].tolist()

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_val)
    y_proba = model.predict_proba(X_val)[:, 1]
    print("===== SQLi DETECTOR REPORT =====")
    print(classification_report(y_val, y_pred))
    print('ROC AUC (SQLi):', roc_auc_score(y_val, y_proba))

    os.makedirs('models', exist_ok=True)
    joblib.dump(model, os.path.join('models', 'sqli_detector.pkl'))
else:
    print("❌ sqli_dataset.csv 파일이 존재하지 않습니다.")

# ========== 🔹 XSS 모델 학습 및 저장 ==========

XSS_DATA_PATH = os.path.join(os.getcwd(), 'data', 'xss_dataset.csv')
if os.path.exists(XSS_DATA_PATH):
    print("📥 XSS 데이터 로드 중...")
    data_xss = pd.read_csv(XSS_DATA_PATH)

    # 열 이름 강제 재지정 (value, label 기준으로)
    if data_xss.shape[1] >= 2:
        data_xss.columns = ['value', 'label'] + list(data_xss.columns[2:])

        X_xss = data_xss['value'].apply(lambda v: vectorize_input("-", "-", str(v))).tolist()
        y_xss = data_xss['label'].tolist()

        X_train_xss, X_val_xss, y_train_xss, y_val_xss = train_test_split(X_xss, y_xss, test_size=0.2, random_state=42)

        model_xss = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
        model_xss.fit(X_train_xss, y_train_xss)

        y_pred_xss = model_xss.predict(X_val_xss)
        y_proba_xss = model_xss.predict_proba(X_val_xss)[:, 1]
        print("===== XSS DETECTOR REPORT =====")
        print(classification_report(y_val_xss, y_pred_xss))

        try:
            print('ROC AUC (XSS):', roc_auc_score(y_val_xss, y_proba_xss))
        except ValueError:
            print("⚠ ROC AUC (XSS): 계산 실패 (클래스가 하나뿐임)")

        os.makedirs('models', exist_ok=True)
        joblib.dump(model_xss, os.path.join('models', 'xss_detector.pkl'))
    else:
        print("❌ xss_dataset.csv에 필요한 열(value, label)이 부족합니다.")
else:
    print("⚠️ xss_dataset.csv 파일이 존재하지 않습니다.")