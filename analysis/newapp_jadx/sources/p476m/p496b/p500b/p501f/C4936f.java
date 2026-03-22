package p476m.p496b.p500b.p501f;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

/* renamed from: m.b.b.f.f */
/* loaded from: classes3.dex */
public class C4936f implements InterfaceC4931a {

    /* renamed from: a */
    public final SQLiteDatabase f12587a;

    public C4936f(SQLiteDatabase sQLiteDatabase) {
        this.f12587a = sQLiteDatabase;
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    /* renamed from: a */
    public Object mo5604a() {
        return this.f12587a;
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    /* renamed from: b */
    public Cursor mo5605b(String str, String[] strArr) {
        return this.f12587a.rawQuery(str, strArr);
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public void beginTransaction() {
        this.f12587a.beginTransaction();
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public InterfaceC4933c compileStatement(String str) {
        return new C4937g(this.f12587a.compileStatement(str));
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public void endTransaction() {
        this.f12587a.endTransaction();
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public void execSQL(String str) {
        this.f12587a.execSQL(str);
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public boolean isDbLockedByCurrentThread() {
        return this.f12587a.isDbLockedByCurrentThread();
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public void setTransactionSuccessful() {
        this.f12587a.setTransactionSuccessful();
    }
}
