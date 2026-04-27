package com.litesuits.orm.db.assit;

import android.database.sqlite.SQLiteDatabase;
import com.litesuits.orm.log.OrmLog;

/* JADX INFO: loaded from: classes3.dex */
public class Transaction {
    private static final String TAG = Transaction.class.getSimpleName();

    public interface Worker<T> {
        T doTransaction(SQLiteDatabase sQLiteDatabase) throws Exception;
    }

    public static <T> T execute(SQLiteDatabase db, Worker<T> worker) {
        db.beginTransaction();
        OrmLog.i(TAG, "----> BeginTransaction");
        T data = null;
        try {
            try {
                data = worker.doTransaction(db);
                db.setTransactionSuccessful();
                if (OrmLog.isPrint) {
                    OrmLog.i(TAG, "----> Transaction Successful");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return data;
        } finally {
            db.endTransaction();
        }
    }
}
