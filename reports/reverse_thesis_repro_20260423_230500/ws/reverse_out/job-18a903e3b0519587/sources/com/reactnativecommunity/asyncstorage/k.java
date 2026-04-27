package com.reactnativecommunity.asyncstorage;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;

/* JADX INFO: loaded from: classes.dex */
public class k extends SQLiteOpenHelper {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static k f8525e;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Context f8526b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private SQLiteDatabase f8527c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private long f8528d;

    private k(Context context) {
        super(context, "RKStorage", (SQLiteDatabase.CursorFactory) null, 1);
        this.f8528d = j.f8524a.longValue() * 1048576;
        this.f8526b = context;
    }

    private synchronized boolean p() {
        i();
        return this.f8526b.deleteDatabase("RKStorage");
    }

    public static k x(Context context) {
        if (f8525e == null) {
            f8525e = new k(context.getApplicationContext());
        }
        return f8525e;
    }

    synchronized void b() {
        v().delete("catalystLocalStorage", null, null);
    }

    public synchronized void i() {
        SQLiteDatabase sQLiteDatabase = this.f8527c;
        if (sQLiteDatabase != null && sQLiteDatabase.isOpen()) {
            this.f8527c.close();
            this.f8527c = null;
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onCreate(SQLiteDatabase sQLiteDatabase) {
        sQLiteDatabase.execSQL("CREATE TABLE catalystLocalStorage (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i3, int i4) {
        if (i3 != i4) {
            p();
            onCreate(sQLiteDatabase);
        }
    }

    synchronized boolean r() {
        SQLiteDatabase sQLiteDatabase = this.f8527c;
        if (sQLiteDatabase != null && sQLiteDatabase.isOpen()) {
            return true;
        }
        SQLiteException e3 = null;
        for (int i3 = 0; i3 < 2; i3++) {
            if (i3 > 0) {
                try {
                    p();
                } catch (SQLiteException e4) {
                    e3 = e4;
                    try {
                        Thread.sleep(30L);
                    } catch (InterruptedException unused) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
            this.f8527c = getWritableDatabase();
        }
        SQLiteDatabase sQLiteDatabase2 = this.f8527c;
        if (sQLiteDatabase2 == null) {
            throw e3;
        }
        sQLiteDatabase2.setMaximumSize(this.f8528d);
        return true;
    }

    public synchronized SQLiteDatabase v() {
        r();
        return this.f8527c;
    }
}
