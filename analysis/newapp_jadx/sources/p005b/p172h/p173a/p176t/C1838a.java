package p005b.p172h.p173a.p176t;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import java.util.Objects;
import p005b.p172h.p173a.C1828q;
import tv.danmaku.ijk.media.player.misc.IMediaFormat;

/* renamed from: b.h.a.t.a */
/* loaded from: classes.dex */
public class C1838a extends SQLiteOpenHelper implements InterfaceC1840c {

    /* renamed from: c */
    public static final String[] f2840c = {"_id", "url", "length", IMediaFormat.KEY_MIME};

    public C1838a(Context context) {
        super(context, "AndroidVideoCache.db", (SQLiteDatabase.CursorFactory) null, 1);
        Objects.requireNonNull(context);
    }

    @Override // p005b.p172h.p173a.p176t.InterfaceC1840c
    /* renamed from: b */
    public void mo1191b(String str, C1828q c1828q) {
        Object[] objArr = {str, c1828q};
        for (int i2 = 0; i2 < 2; i2++) {
            Objects.requireNonNull(objArr[i2]);
        }
        boolean z = get(str) != null;
        ContentValues contentValues = new ContentValues();
        contentValues.put("url", c1828q.f2830a);
        contentValues.put("length", Long.valueOf(c1828q.f2831b));
        contentValues.put(IMediaFormat.KEY_MIME, c1828q.f2832c);
        if (z) {
            getWritableDatabase().update("SourceInfo", contentValues, "url=?", new String[]{str});
        } else {
            getWritableDatabase().insert("SourceInfo", null, contentValues);
        }
    }

    @Override // p005b.p172h.p173a.p176t.InterfaceC1840c
    public C1828q get(String str) {
        Throwable th;
        Cursor cursor;
        Objects.requireNonNull(str);
        C1828q c1828q = null;
        try {
            cursor = getReadableDatabase().query("SourceInfo", f2840c, "url=?", new String[]{str}, null, null, null);
            if (cursor != null) {
                try {
                    if (cursor.moveToFirst()) {
                        c1828q = new C1828q(cursor.getString(cursor.getColumnIndexOrThrow("url")), cursor.getLong(cursor.getColumnIndexOrThrow("length")), cursor.getString(cursor.getColumnIndexOrThrow(IMediaFormat.KEY_MIME)));
                    }
                } catch (Throwable th2) {
                    th = th2;
                    if (cursor != null) {
                        cursor.close();
                    }
                    throw th;
                }
            }
            if (cursor != null) {
                cursor.close();
            }
            return c1828q;
        } catch (Throwable th3) {
            th = th3;
            cursor = null;
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onCreate(SQLiteDatabase sQLiteDatabase) {
        Objects.requireNonNull(sQLiteDatabase);
        sQLiteDatabase.execSQL("CREATE TABLE SourceInfo (_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,url TEXT NOT NULL,mime TEXT,length INTEGER);");
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i2, int i3) {
        throw new IllegalStateException("Should not be called. There is no any migration");
    }

    @Override // p005b.p172h.p173a.p176t.InterfaceC1840c
    public void release() {
        close();
    }
}
