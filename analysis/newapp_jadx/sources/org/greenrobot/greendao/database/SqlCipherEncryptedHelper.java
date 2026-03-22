package org.greenrobot.greendao.database;

import android.content.Context;
import java.util.Objects;
import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteOpenHelper;
import p005b.p006a.p007a.p008a.p016q.C0915e;
import p476m.p496b.p500b.p501f.AbstractC4932b;
import p476m.p496b.p500b.p501f.C4934d;
import p476m.p496b.p500b.p501f.InterfaceC4931a;

/* loaded from: classes3.dex */
public class SqlCipherEncryptedHelper extends SQLiteOpenHelper {
    private final AbstractC4932b delegate;

    public SqlCipherEncryptedHelper(AbstractC4932b abstractC4932b, Context context, String str, int i2, boolean z) {
        super(context, str, (SQLiteDatabase.CursorFactory) null, i2);
        this.delegate = abstractC4932b;
        if (z) {
            SQLiteDatabase.loadLibs(context);
        }
    }

    private InterfaceC4931a wrap(SQLiteDatabase sQLiteDatabase) {
        return new C4934d(sQLiteDatabase);
    }

    public InterfaceC4931a getEncryptedReadableDb(String str) {
        return wrap(getReadableDatabase(str));
    }

    public InterfaceC4931a getEncryptedWritableDb(String str) {
        return wrap(getWritableDatabase(str));
    }

    public void onCreate(SQLiteDatabase sQLiteDatabase) {
        this.delegate.mo217b(wrap(sQLiteDatabase));
    }

    public void onOpen(SQLiteDatabase sQLiteDatabase) {
        AbstractC4932b abstractC4932b = this.delegate;
        wrap(sQLiteDatabase);
        Objects.requireNonNull(abstractC4932b);
    }

    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i2, int i3) {
        AbstractC4932b abstractC4932b = this.delegate;
        InterfaceC4931a wrap = wrap(sQLiteDatabase);
        C0915e c0915e = (C0915e) abstractC4932b;
        Objects.requireNonNull(c0915e);
        wrap.execSQL("DROP TABLE IF EXISTS \"UPLOAD_BEAN\"");
        c0915e.mo217b(wrap);
    }

    public InterfaceC4931a getEncryptedReadableDb(char[] cArr) {
        return wrap(getReadableDatabase(cArr));
    }

    public InterfaceC4931a getEncryptedWritableDb(char[] cArr) {
        return wrap(getWritableDatabase(cArr));
    }
}
