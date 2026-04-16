import sqlite3
import os
import pandas as pd
from datetime import datetime

def get_db_connection():
    db_path = os.path.join("/tmp", "signals.db")
    conn = sqlite3.connect(db_path, check_same_thread=False)
    return conn

def save_to_db(df):
    if df.empty:
        return
    conn = get_db_connection()
    df_to_save = df.copy()
    df_to_save['saved_at'] = datetime.now()
    df_to_save.to_sql("signals", conn, if_exists='append', index=False)
    conn.close()

def load_from_db(limit=50):
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(f"SELECT * FROM signals ORDER BY saved_at DESC LIMIT {limit}", conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df

def format_display_time(timestamp):
    return timestamp.strftime('%H:%M - %d %b') if timestamp else ""
