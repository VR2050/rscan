package com.litesuits.orm.db.assit;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

/* JADX INFO: loaded from: classes3.dex */
public class SQLiteHelper extends SQLiteOpenHelper {
    private OnUpdateListener onUpdateListener;

    public interface OnUpdateListener {
        void onUpdate(SQLiteDatabase sQLiteDatabase, int i, int i2);
    }

    public SQLiteHelper(Context context, String name, SQLiteDatabase.CursorFactory factory, int version, OnUpdateListener onUpdateListener) {
        super(context, name, factory, version);
        this.onUpdateListener = onUpdateListener;
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onCreate(SQLiteDatabase db) {
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        OnUpdateListener onUpdateListener = this.onUpdateListener;
        if (onUpdateListener != null) {
            onUpdateListener.onUpdate(db, oldVersion, newVersion);
        }
    }
}
