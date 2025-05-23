from flask import Flask, render_template, jsonify, send_file
import pandas as pd
import joblib
import numpy as np
import requests
import time

TELEGRAM_TOKEN = "7912135540:AAFIahSGzr7cR_KoAnrVHyABqWoqSsq2Tj8"
CHAT_ID = -1002642262765

shown_attacks = []
operators = ['lecturetographer_tv_22', 'Otterrazan']

def send_telegram_alert(msg):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": ' '.join([f"@{op}" for op in operators]) + '\n' + msg}
    try:
        requests.post(url, data=payload, timeout=3)
    except Exception as e:
        print("Telegram error:", e)

app = Flask(__name__)

df = pd.read_csv("../data/processed/processed_data.csv")
model = joblib.load("../models/kmeans_model.pkl")
scaler = joblib.load("../models/scaler.pkl")

feature_cols = [
    'flow_duration', 'fwd_pkts_tot', 'bwd_pkts_tot', 'payload_bytes_per_second',
    'fwd_pkts_payload.avg', 'flow_pkts_payload.std', 'fwd_iat.avg', 'bwd_iat.avg',
    'flow_iat.std', 'flow_FIN_flag_count', 'flow_SYN_flag_count', 'down_up_ratio'
]

X = df[feature_cols]
df["cluster"] = model.predict(X)
attacker_cluster = df.groupby("cluster")["label"].mean().idxmin()
df["status"] = df["cluster"].apply(lambda x: "Атака" if x == attacker_cluster else "Норма")

proto_blacklist = pd.read_csv("../data/blacklist_protocols.csv")
port_blacklist = pd.read_csv("../data/blacklist_ports.csv")
danger_proto = set(proto_blacklist["proto"].astype(str))
danger_ports = set(port_blacklist["id.orig_p"].astype(int))

def risk(proto, port, cluster):
    if cluster == attacker_cluster and (proto in danger_proto or port in danger_ports):
        return "🔥 Високий"
    elif cluster == attacker_cluster:
        return "⚠️ Середній"
    return "✅ Низький"

df["Ризик"] = df.apply(lambda row: risk(str(row["proto"]), int(row["id.orig_p"]), row["cluster"]), axis=1)

def get_real_payload(row):
    scaled_row = np.array([row[feature_cols].values])
    original_row = scaler.inverse_transform(scaled_row)[0]
    return float(original_row[feature_cols.index("payload_bytes_per_second")])

@app.route("/")
def dashboard():
    sample_df = df.sample(100, random_state=42).copy()
    sample_df["Payload (B/s)"] = sample_df.apply(get_real_payload, axis=1)
    sample_df_view = sample_df[["proto", "id.orig_p", "Payload (B/s)", "status", "Ризик"]]
    sample_df_view.columns = ["Протокол", "Порт", "Payload (B/s)", "Статус", "Рівень ризику"]
    return render_template("dashboard.html", table=sample_df_view.to_dict(orient="records"))

last_alert_time = 0

@app.route("/api/data")
def api_data():
    global last_alert_time
    sample = df.sample(1).iloc[0]
    scaled_row = np.array([sample[feature_cols].values])
    original_row = scaler.inverse_transform(scaled_row)[0]
    payload_real = float(original_row[feature_cols.index("payload_bytes_per_second")])

    if sample["status"] == "Атака":
        attack_data = {
            "Протокол": sample["proto"],
            "Порт": int(sample["id.orig_p"]),
            "Payload (B/s)": payload_real,
            "Рівень ризику": sample["Ризик"]
        }:
        if attack_data not in shown_attacks:
            shown_attacks.append(attack_data)

    if sample["status"] == "Атака":
        now = time.time()
        if now - last_alert_time > 5:
            try:
                send_telegram_alert(
                    f"🚨 Атака виявлена!\n"
                    f"Протокол: {sample['proto']}\n"
                    f"Порт: {sample['id.orig_p']}\n"
                    f"Payload: {payload_real:.2f} B/s"
                )
                last_alert_time = now
            except Exception as e:
                print("Telegram error:", e)

    return jsonify({
        "Протокол": sample["proto"],
        "Порт": int(sample["id.orig_p"]),
        "Payload (B/s)": payload_real,
        "Статус": sample["status"],
        "Рівень ризику": sample["Ризик"]
    })

@app.route("/download_report")
def download_report():
    import io
    from datetime import datetime
    import matplotlib.pyplot as plt
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.utils import ImageReader

    if not shown_attacks:
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        c.setFont("Helvetica", 14)
        c.drawString(72, 700, "No attacks detected during this session.")
        c.save()
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name="threats_report.pdf")

    df_report = pd.DataFrame(shown_attacks)
    risk_map = {
    "🔥 Високий": "High",
    "⚠️ Середній": "Medium",
    "✅ Низький": "Low"
    }

    df_report.columns = ["Protocol", "Port", "Payload (B/s)", "Risk Level"]
    df_report["Risk Level"] = df_report["Risk Level"].map(risk_map).fillna(df_report["Risk Level"])
    total = len(df_report)
    proto_dist = df_report['Protocol'].value_counts(normalize=True) * 100
    risk_dist = df_report['Risk Level'].value_counts()
    avg_payload = df_report['Payload (B/s)'].mean()
    max_payload = df_report['Payload (B/s)'].max()

    plt.figure(figsize=(5,3))
    proto_dist.sort_values().plot(kind='barh', color='orange')
    plt.title('Attack percentage by protocol')
    plt.xlabel('% of attacks')
    plt.ylabel('Protocol')
    plt.tight_layout()
    img_buf = io.BytesIO()
    plt.savefig(img_buf, format='png')
    plt.close()
    img_buf.seek(0)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    textobject = c.beginText(40, 750)
    textobject.setFont("Helvetica-Bold", 15)
    textobject.textLine(f"ANOMALY DETECTION REPORT ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    textobject.setFont("Helvetica", 11)
    textobject.textLine("")
    textobject.textLine(f"Total attacks: {total}")
    textobject.textLine(f"Mean payload: {avg_payload:.2f} B/s")
    textobject.textLine(f"Max payload: {max_payload:.2f} B/s")
    textobject.textLine("")
    textobject.textLine("Attack percentage by protocol:")
    for proto, pct in proto_dist.items():
        textobject.textLine(f"   - {proto}: {pct:.1f}%")
    textobject.textLine("")
    textobject.textLine("Attack count by risk level:")
    for risk, cnt in risk_dist.items():
        textobject.textLine(f"   - {risk}: {cnt}")
    textobject.textLine("")
    textobject.textLine("Attack sample table below ⬇️")
    c.drawText(textobject)

    c.drawImage(ImageReader(img_buf), 45, 470, width=350, height=170)

    df_table = df_report.head(10)
    table_data = [list(df_table.columns)] + [list(map(str, row)) for row in df_table.itertuples(index=False)]
    table = Table(table_data, colWidths=[80, 60, 110, 100])
    style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTSIZE', (0,0), (-1,-1), 9)
    ])
    table.setStyle(style)
    table.wrapOn(c, 60, 200)
    table.drawOn(c, 50, 320)

    c.save()
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"ANOMALY DETECTION REPORT ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}).pdf")

if __name__ == "__main__":
    app.run(debug=True)




