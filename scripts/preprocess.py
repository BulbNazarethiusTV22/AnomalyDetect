#Вибрані фічі:
# flow_duration = Тривалість з’єднання (у секундах)
# fwd_pkts_tot = Загальна кількість forward-пакетів (від клієнта до сервера)
# bwd_pkts_tot = Загальна кількість backward-пакетів (від сервера до клієнта)
# payload_bytes_per_second = Інтенсивність — байти в секунду (весь трафік з payload'ом)
# fwd_pkts_payload.avg = Середній розмір payload forward-пакетів
# flow_pkts_payload.std = Стандартне відхилення розміру payload — флуктуації
# fwd_iat.avg = Середній час між forward-пакетами
# bwd_iat.avg = Середній час між backward-пакетами
# flow_iat.std = Варіативність інтервалів між будь-якими пакетами
# flow_FIN_flag_count = Кількість FIN-флагів (кінець TCP-сесії)
# flow_SYN_flag_count = Кількість SYN-флагів (початок TCP-сесії)
# down_up_ratio = Співвідношення обсягу отриманих/відправлених байтів
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

INPUT_PATH = "../data/raw/RT_IOT2022.csv"
OUTPUT_PATH = "../data/processed/processed_data.csv"
SCALER_PATH = "../models/scaler.pkl"

SELECTED_FEATURES = [
    'flow_duration', 'fwd_pkts_tot', 'bwd_pkts_tot', 'payload_bytes_per_second',
    'fwd_pkts_payload.avg', 'flow_pkts_payload.std', 'fwd_iat.avg', 'bwd_iat.avg',
    'flow_iat.std', 'flow_FIN_flag_count', 'flow_SYN_flag_count', 'down_up_ratio'
]

NORMAL_LABELS = ['Thing_Speak', 'Wipro_bulb', 'MQTT_Publish']
# Thing_Speak - Це онлайн-сервіс для збирання і візуалізації даних з IoT-пристроїв; Працює як платформа для сенсорів: надсилає показники температури, вологості тощо
# Wipro_bulb - Це розумна лампочка виробництва Wipro (індійський бренд); Може отримувати команди через Wi-Fi: ввімкнути, змінити колір, яскравість
# MQTT_Publish - MQTT — популярний легкий протокол для IoT (publish/subscribe); MQTT_Publish означає, що пристрій надсилає повідомлення на сервер (брокер)

def preprocess():
    df = pd.read_csv(INPUT_PATH)
    df = df[SELECTED_FEATURES + ['Attack_type', 'proto', 'id.orig_p']].dropna()

    df['label'] = (~df['Attack_type'].isin(NORMAL_LABELS)).astype(int)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df[SELECTED_FEATURES])

    df_scaled = pd.DataFrame(X_scaled, columns=SELECTED_FEATURES)
    df_scaled['Attack_type'] = df['Attack_type'].values
    df_scaled['proto'] = df['proto'].values
    df_scaled['id.orig_p'] = df['id.orig_p'].values
    df_scaled['label'] = df['label'].values

    df_scaled.to_csv(OUTPUT_PATH, index=False)
    joblib.dump(scaler, SCALER_PATH)

if __name__ == "__main__":
    preprocess()

