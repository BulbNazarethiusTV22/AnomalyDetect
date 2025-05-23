import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report, confusion_matrix
import joblib

INPUT_PATH = "../data/processed/processed_data.csv"
MODEL_PATH = "../models/kmeans_model.pkl"
BLACKLIST_PROTO_PATH = "../data/blacklist_protocols.csv"
BLACKLIST_PORT_PATH = "../data/blacklist_ports.csv"

N_CLUSTERS = 2


def train_kmeans():
    df = pd.read_csv(INPUT_PATH)
    feature_cols = df.drop(columns=["Attack_type", "label", "proto", "id.orig_p"]).columns

    model = KMeans(n_clusters=N_CLUSTERS, random_state=42, n_init=10)
    df["cluster"] = model.fit_predict(df[feature_cols])

    joblib.dump(model, MODEL_PATH)
    print("Модель KMeans збережено", MODEL_PATH)

    print("\nТоп-5 типів атак у кластері 1:")
    top_attacks = df[df.cluster == 1]["Attack_type"].value_counts().head(5)
    print(top_attacks)

    if "proto" in df.columns:
        blacklist_proto = df[df.cluster == 1]["proto"].value_counts().head(10)
        blacklist_proto.to_csv(BLACKLIST_PROTO_PATH, header=["frequency"])
        print("\nBlacklist-протоколи збережено у:", BLACKLIST_PROTO_PATH)

    if "id.orig_p" in df.columns:
        blacklist_ports = df[df.cluster == 1]["id.orig_p"].value_counts().head(20)
        blacklist_ports.to_csv(BLACKLIST_PORT_PATH, header=["frequency"])
        print("\nBlacklist-порти збережено у:", BLACKLIST_PORT_PATH)

    predicted = (df["cluster"] == 1).astype(int)
    report = classification_report(df["label"], predicted, target_names=["Норма", "Атака"])
    print("\nЗвіт про класифікацію (кластер vs label):")
    print(report)

    cm = confusion_matrix(df["label"], predicted)
    print("\nConfusion Matrix:")
    print(cm)

if __name__ == "__main__":
    train_kmeans()

