package p005b.p199l.p200a.p201a.p208f1.p211c0;

import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.c0.a */
/* loaded from: classes.dex */
public abstract class AbstractC1981a {

    /* renamed from: a */
    public final int f3584a;

    /* renamed from: b.l.a.a.f1.c0.a$a */
    public static final class a extends AbstractC1981a {

        /* renamed from: b */
        public final long f3585b;

        /* renamed from: c */
        public final List<b> f3586c;

        /* renamed from: d */
        public final List<a> f3587d;

        public a(int i2, long j2) {
            super(i2);
            this.f3585b = j2;
            this.f3586c = new ArrayList();
            this.f3587d = new ArrayList();
        }

        @Nullable
        /* renamed from: b */
        public a m1510b(int i2) {
            int size = this.f3587d.size();
            for (int i3 = 0; i3 < size; i3++) {
                a aVar = this.f3587d.get(i3);
                if (aVar.f3584a == i2) {
                    return aVar;
                }
            }
            return null;
        }

        @Nullable
        /* renamed from: c */
        public b m1511c(int i2) {
            int size = this.f3586c.size();
            for (int i3 = 0; i3 < size; i3++) {
                b bVar = this.f3586c.get(i3);
                if (bVar.f3584a == i2) {
                    return bVar;
                }
            }
            return null;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p211c0.AbstractC1981a
        public String toString() {
            return AbstractC1981a.m1509a(this.f3584a) + " leaves: " + Arrays.toString(this.f3586c.toArray()) + " containers: " + Arrays.toString(this.f3587d.toArray());
        }
    }

    /* renamed from: b.l.a.a.f1.c0.a$b */
    public static final class b extends AbstractC1981a {

        /* renamed from: b */
        public final C2360t f3588b;

        public b(int i2, C2360t c2360t) {
            super(i2);
            this.f3588b = c2360t;
        }
    }

    public AbstractC1981a(int i2) {
        this.f3584a = i2;
    }

    /* renamed from: a */
    public static String m1509a(int i2) {
        StringBuilder m586H = C1499a.m586H("");
        m586H.append((char) ((i2 >> 24) & 255));
        m586H.append((char) ((i2 >> 16) & 255));
        m586H.append((char) ((i2 >> 8) & 255));
        m586H.append((char) (i2 & 255));
        return m586H.toString();
    }

    public String toString() {
        return m1509a(this.f3584a);
    }
}
