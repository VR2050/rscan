package p476m.p496b.p500b.p501f;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import p005b.p006a.p007a.p008a.p016q.C0915e;

/* renamed from: m.b.b.f.b */
/* loaded from: classes3.dex */
public abstract class AbstractC4932b extends SQLiteOpenHelper {
    public AbstractC4932b(Context context, String str, int i2) {
        super(context, str, (SQLiteDatabase.CursorFactory) null, i2);
    }

    /* renamed from: b */
    public abstract void mo217b(InterfaceC4931a interfaceC4931a);

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onCreate(SQLiteDatabase sQLiteDatabase) {
        mo217b(new C4936f(sQLiteDatabase));
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onOpen(SQLiteDatabase sQLiteDatabase) {
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i2, int i3) {
        C4936f c4936f = new C4936f(sQLiteDatabase);
        sQLiteDatabase.execSQL("DROP TABLE IF EXISTS \"UPLOAD_BEAN\"");
        ((C0915e) this).mo217b(c4936f);
    }
}
