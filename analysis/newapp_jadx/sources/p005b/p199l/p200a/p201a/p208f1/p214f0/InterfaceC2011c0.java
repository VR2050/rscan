package p005b.p199l.p200a.p201a.p208f1.p214f0;

import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.c0 */
/* loaded from: classes.dex */
public interface InterfaceC2011c0 {

    /* renamed from: b.l.a.a.f1.f0.c0$a */
    public static final class a {

        /* renamed from: a */
        public final String f3853a;

        /* renamed from: b */
        public final byte[] f3854b;

        public a(String str, int i2, byte[] bArr) {
            this.f3853a = str;
            this.f3854b = bArr;
        }
    }

    /* renamed from: b.l.a.a.f1.f0.c0$b */
    public static final class b {

        /* renamed from: a */
        public final int f3855a;

        /* renamed from: b */
        public final String f3856b;

        /* renamed from: c */
        public final List<a> f3857c;

        /* renamed from: d */
        public final byte[] f3858d;

        public b(int i2, String str, List<a> list, byte[] bArr) {
            this.f3855a = i2;
            this.f3856b = str;
            this.f3857c = list == null ? Collections.emptyList() : Collections.unmodifiableList(list);
            this.f3858d = bArr;
        }
    }

    /* renamed from: b.l.a.a.f1.f0.c0$c */
    public interface c {
        /* renamed from: a */
        InterfaceC2011c0 mo1583a(int i2, b bVar);
    }

    /* renamed from: b.l.a.a.f1.f0.c0$d */
    public static final class d {

        /* renamed from: a */
        public final String f3859a;

        /* renamed from: b */
        public final int f3860b;

        /* renamed from: c */
        public final int f3861c;

        /* renamed from: d */
        public int f3862d;

        /* renamed from: e */
        public String f3863e;

        public d(int i2, int i3, int i4) {
            String str;
            if (i2 != Integer.MIN_VALUE) {
                str = i2 + "/";
            } else {
                str = "";
            }
            this.f3859a = str;
            this.f3860b = i3;
            this.f3861c = i4;
            this.f3862d = Integer.MIN_VALUE;
        }

        /* renamed from: a */
        public void m1584a() {
            int i2 = this.f3862d;
            this.f3862d = i2 == Integer.MIN_VALUE ? this.f3860b : i2 + this.f3861c;
            this.f3863e = this.f3859a + this.f3862d;
        }

        /* renamed from: b */
        public String m1585b() {
            if (this.f3862d != Integer.MIN_VALUE) {
                return this.f3863e;
            }
            throw new IllegalStateException("generateNewId() must be called before retrieving ids.");
        }

        /* renamed from: c */
        public int m1586c() {
            int i2 = this.f3862d;
            if (i2 != Integer.MIN_VALUE) {
                return i2;
            }
            throw new IllegalStateException("generateNewId() must be called before retrieving ids.");
        }
    }

    /* renamed from: a */
    void mo1580a(C2342c0 c2342c0, InterfaceC2042i interfaceC2042i, d dVar);

    /* renamed from: b */
    void mo1581b(C2360t c2360t, int i2);

    /* renamed from: c */
    void mo1582c();
}
