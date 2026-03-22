package p476m.p496b.p500b.p501f;

import android.database.Cursor;
import net.sqlcipher.database.SQLiteDatabase;

/* renamed from: m.b.b.f.d */
/* loaded from: classes3.dex */
public class C4934d implements InterfaceC4931a {

    /* renamed from: a */
    public final SQLiteDatabase f12585a;

    public C4934d(SQLiteDatabase sQLiteDatabase) {
        this.f12585a = sQLiteDatabase;
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    /* renamed from: a */
    public Object mo5604a() {
        return this.f12585a;
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    /* renamed from: b */
    public Cursor mo5605b(String str, String[] strArr) {
        return this.f12585a.rawQuery(str, strArr);
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public void beginTransaction() {
        this.f12585a.beginTransaction();
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public InterfaceC4933c compileStatement(String str) {
        return new C4935e(this.f12585a.compileStatement(str));
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public void endTransaction() {
        this.f12585a.endTransaction();
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public void execSQL(String str) {
        this.f12585a.execSQL(str);
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public boolean isDbLockedByCurrentThread() {
        return this.f12585a.isDbLockedByCurrentThread();
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4931a
    public void setTransactionSuccessful() {
        this.f12585a.setTransactionSuccessful();
    }
}
