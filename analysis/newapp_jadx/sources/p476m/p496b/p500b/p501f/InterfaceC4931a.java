package p476m.p496b.p500b.p501f;

import android.database.Cursor;

/* renamed from: m.b.b.f.a */
/* loaded from: classes3.dex */
public interface InterfaceC4931a {
    /* renamed from: a */
    Object mo5604a();

    /* renamed from: b */
    Cursor mo5605b(String str, String[] strArr);

    void beginTransaction();

    InterfaceC4933c compileStatement(String str);

    void endTransaction();

    void execSQL(String str);

    boolean isDbLockedByCurrentThread();

    void setTransactionSuccessful();
}
