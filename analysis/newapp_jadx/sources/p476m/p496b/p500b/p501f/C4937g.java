package p476m.p496b.p500b.p501f;

import android.database.sqlite.SQLiteStatement;

/* renamed from: m.b.b.f.g */
/* loaded from: classes3.dex */
public class C4937g implements InterfaceC4933c {

    /* renamed from: a */
    public final SQLiteStatement f12588a;

    public C4937g(SQLiteStatement sQLiteStatement) {
        this.f12588a = sQLiteStatement;
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4933c
    public void bindLong(int i2, long j2) {
        this.f12588a.bindLong(i2, j2);
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4933c
    public void bindString(int i2, String str) {
        this.f12588a.bindString(i2, str);
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4933c
    public void close() {
        this.f12588a.close();
    }

    @Override // p476m.p496b.p500b.p501f.InterfaceC4933c
    public void execute() {
        this.f12588a.execute();
    }
}
