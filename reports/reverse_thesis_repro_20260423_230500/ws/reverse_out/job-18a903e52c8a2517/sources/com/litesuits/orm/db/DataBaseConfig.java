package com.litesuits.orm.db;

import android.content.Context;
import com.litesuits.orm.db.assit.Checker;
import com.litesuits.orm.db.assit.SQLiteHelper;

/* JADX INFO: loaded from: classes3.dex */
public class DataBaseConfig {
    public static final String DEFAULT_DB_NAME = "liteorm.db";
    public static final int DEFAULT_DB_VERSION = 1;
    public Context context;
    public String dbName;
    public int dbVersion;
    public boolean debugged;
    public SQLiteHelper.OnUpdateListener onUpdateListener;

    public DataBaseConfig(Context context) {
        this(context, DEFAULT_DB_NAME);
    }

    public DataBaseConfig(Context context, String dbName) {
        this(context, dbName, false, 1, null);
    }

    public DataBaseConfig(Context context, String dbName, boolean debugged, int dbVersion, SQLiteHelper.OnUpdateListener onUpdateListener) {
        this.debugged = false;
        this.dbName = DEFAULT_DB_NAME;
        this.dbVersion = 1;
        this.context = context.getApplicationContext();
        if (!Checker.isEmpty(dbName)) {
            this.dbName = dbName;
        }
        if (dbVersion > 1) {
            this.dbVersion = dbVersion;
        }
        this.debugged = debugged;
        this.onUpdateListener = onUpdateListener;
    }

    public String toString() {
        return "DataBaseConfig [mContext=" + this.context + ", mDbName=" + this.dbName + ", mDbVersion=" + this.dbVersion + ", mOnUpdateListener=" + this.onUpdateListener + "]";
    }
}
