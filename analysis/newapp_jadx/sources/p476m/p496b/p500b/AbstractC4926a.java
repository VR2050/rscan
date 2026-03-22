package p476m.p496b.p500b;

import android.database.CrossProcessCursor;
import android.database.Cursor;
import android.database.CursorWindow;
import android.database.sqlite.SQLiteDatabase;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p496b.p500b.p501f.InterfaceC4931a;
import p476m.p496b.p500b.p501f.InterfaceC4933c;
import p476m.p496b.p500b.p502g.C4939b;
import p476m.p496b.p500b.p502g.InterfaceC4938a;
import p476m.p496b.p500b.p503h.C4942a;
import p476m.p496b.p500b.p503h.C4946e;

/* renamed from: m.b.b.a */
/* loaded from: classes3.dex */
public abstract class AbstractC4926a<T, K> {

    /* renamed from: a */
    public final C4942a f12572a;

    /* renamed from: b */
    public final InterfaceC4931a f12573b;

    /* renamed from: c */
    public final InterfaceC4938a<K, T> f12574c;

    /* renamed from: d */
    public final C4939b<T> f12575d;

    /* renamed from: e */
    public final C4946e f12576e;

    /* renamed from: f */
    public final int f12577f;

    public AbstractC4926a(C4942a c4942a, C4927b c4927b) {
        this.f12572a = c4942a;
        InterfaceC4931a interfaceC4931a = c4942a.f12596c;
        this.f12573b = interfaceC4931a;
        boolean z = interfaceC4931a.mo5604a() instanceof SQLiteDatabase;
        C4939b<T> c4939b = (InterfaceC4938a<K, T>) c4942a.f12605m;
        this.f12574c = c4939b;
        if (c4939b instanceof C4939b) {
            this.f12575d = c4939b;
        } else {
            this.f12575d = null;
        }
        this.f12576e = c4942a.f12604l;
        C4930e c4930e = c4942a.f12602j;
        this.f12577f = c4930e != null ? c4930e.f12580a : -1;
    }

    /* renamed from: a */
    public void m5598a() {
        if (this.f12572a.f12600h.length == 1) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(this);
        sb.append(" (");
        throw new C4928c(C1499a.m582D(sb, this.f12572a.f12597e, ") does not have a single-column primary key"));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: b */
    public final void m5599b(K k2, InterfaceC4933c interfaceC4933c) {
        if (k2 instanceof Long) {
            interfaceC4933c.bindLong(1, ((Long) k2).longValue());
        } else {
            if (k2 == 0) {
                throw new C4928c("Cannot delete entity, key is null");
            }
            interfaceC4933c.bindString(1, k2.toString());
        }
        interfaceC4933c.execute();
    }

    /* renamed from: c */
    public abstract K mo4196c(T t);

    /* JADX WARN: Removed duplicated region for block: B:15:0x0037  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0060  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.List<T> m5600d(android.database.Cursor r7) {
        /*
            r6 = this;
            int r0 = r7.getCount()
            if (r0 != 0) goto Lc
            java.util.ArrayList r7 = new java.util.ArrayList
            r7.<init>()
            return r7
        Lc:
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>(r0)
            r2 = 0
            boolean r3 = r7 instanceof android.database.CrossProcessCursor
            r4 = 0
            if (r3 == 0) goto L30
            r2 = r7
            android.database.CrossProcessCursor r2 = (android.database.CrossProcessCursor) r2
            android.database.CursorWindow r2 = r2.getWindow()
            if (r2 == 0) goto L30
            int r3 = r2.getNumRows()
            if (r3 != r0) goto L2d
            m.b.b.h.b r7 = new m.b.b.h.b
            r7.<init>(r2)
            r3 = 1
            goto L31
        L2d:
            r2.getNumRows()
        L30:
            r3 = 0
        L31:
            boolean r5 = r7.moveToFirst()
            if (r5 == 0) goto L6d
            m.b.b.g.a<K, T> r5 = r6.f12574c
            if (r5 == 0) goto L43
            r5.lock()
            m.b.b.g.a<K, T> r5 = r6.f12574c
            r5.mo5608c(r0)
        L43:
            if (r3 != 0) goto L4f
            if (r2 == 0) goto L4f
            m.b.b.g.a<K, T> r0 = r6.f12574c     // Catch: java.lang.Throwable -> L64
            if (r0 == 0) goto L4f
            r6.m5601e(r7, r2, r1)     // Catch: java.lang.Throwable -> L64
            goto L5c
        L4f:
            java.lang.Object r0 = r6.m5602f(r7, r4, r4)     // Catch: java.lang.Throwable -> L64
            r1.add(r0)     // Catch: java.lang.Throwable -> L64
            boolean r0 = r7.moveToNext()     // Catch: java.lang.Throwable -> L64
            if (r0 != 0) goto L4f
        L5c:
            m.b.b.g.a<K, T> r7 = r6.f12574c
            if (r7 == 0) goto L6d
            r7.unlock()
            goto L6d
        L64:
            r7 = move-exception
            m.b.b.g.a<K, T> r0 = r6.f12574c
            if (r0 == 0) goto L6c
            r0.unlock()
        L6c:
            throw r7
        L6d:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p476m.p496b.p500b.AbstractC4926a.m5600d(android.database.Cursor):java.util.List");
    }

    /* renamed from: e */
    public final void m5601e(Cursor cursor, CursorWindow cursorWindow, List<T> list) {
        int numRows = cursorWindow.getNumRows() + cursorWindow.getStartPosition();
        int i2 = 0;
        while (true) {
            list.add(m5602f(cursor, 0, false));
            int i3 = i2 + 1;
            if (i3 >= numRows) {
                this.f12574c.unlock();
                try {
                    CursorWindow window = cursor.moveToNext() ? ((CrossProcessCursor) cursor).getWindow() : null;
                    if (window == null) {
                        return;
                    } else {
                        numRows = window.getNumRows() + window.getStartPosition();
                    }
                } finally {
                    this.f12574c.lock();
                }
            } else if (!cursor.moveToNext()) {
                return;
            }
            i2 = i3 + 1;
        }
    }

    /* renamed from: f */
    public final T m5602f(Cursor cursor, int i2, boolean z) {
        T t;
        if (this.f12575d != null) {
            if (i2 != 0 && cursor.isNull(this.f12577f + i2)) {
                return null;
            }
            long j2 = cursor.getLong(this.f12577f + i2);
            C4939b<T> c4939b = this.f12575d;
            if (z) {
                t = c4939b.m5609d(j2);
            } else {
                Reference<T> m5612a = c4939b.f12589a.m5612a(j2);
                t = m5612a != null ? m5612a.get() : null;
            }
            if (t != null) {
                return t;
            }
            T mo4197g = mo4197g(cursor, i2);
            if (z) {
                this.f12575d.m5610e(j2, mo4197g);
            } else {
                this.f12575d.f12589a.m5613b(j2, new WeakReference(mo4197g));
            }
            return mo4197g;
        }
        if (this.f12574c == null) {
            if (i2 == 0 || mo4198h(cursor, i2) != null) {
                return mo4197g(cursor, i2);
            }
            return null;
        }
        K mo4198h = mo4198h(cursor, i2);
        if (i2 != 0 && mo4198h == null) {
            return null;
        }
        InterfaceC4938a<K, T> interfaceC4938a = this.f12574c;
        T mo5607b = z ? interfaceC4938a.get(mo4198h) : interfaceC4938a.mo5607b(mo4198h);
        if (mo5607b != null) {
            return mo5607b;
        }
        T mo4197g2 = mo4197g(cursor, i2);
        InterfaceC4938a<K, T> interfaceC4938a2 = this.f12574c;
        if (interfaceC4938a2 != null && mo4198h != null) {
            if (z) {
                interfaceC4938a2.put(mo4198h, mo4197g2);
            } else {
                interfaceC4938a2.mo5606a(mo4198h, mo4197g2);
            }
        }
        return mo4197g2;
    }

    /* renamed from: g */
    public abstract T mo4197g(Cursor cursor, int i2);

    /* renamed from: h */
    public abstract K mo4198h(Cursor cursor, int i2);
}
