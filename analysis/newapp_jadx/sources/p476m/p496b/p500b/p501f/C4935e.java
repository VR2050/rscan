package p476m.p496b.p500b.p501f;

import net.sqlcipher.database.SQLiteStatement;

/* renamed from: m.b.b.f.e */
/* loaded from: classes3.dex */
public class C4935e implements InterfaceC4933c {

    /* renamed from: a */
    public final SQLiteStatement f12586a;

    public C4935e(SQLiteStatement sQLiteStatement) {
        this.f12586a = sQLiteStatement;
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4933c
    public void bindLong(int i2, long j2) {
        this.f12586a.bindLong(i2, j2);
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4933c
    public void bindString(int i2, String str) {
        this.f12586a.bindString(i2, str);
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4933c
    public void close() {
        this.f12586a.close();
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4933c
    public void execute() {
        this.f12586a.execute();
    }
}
