package p005b.p199l.p200a.p201a.p208f1;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.metadata.Metadata;
import java.io.EOFException;
import p005b.p199l.p200a.p201a.p220h1.p223i.C2088b;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.n */
/* loaded from: classes.dex */
public final class C2047n {

    /* renamed from: a */
    public final C2360t f4172a = new C2360t(10);

    @Nullable
    /* renamed from: a */
    public Metadata m1632a(C2003e c2003e, @Nullable C2088b.a aVar) {
        Metadata metadata = null;
        int i2 = 0;
        while (true) {
            try {
                c2003e.m1565e(this.f4172a.f6133a, 0, 10, false);
                this.f4172a.m2567C(0);
                if (this.f4172a.m2587s() != 4801587) {
                    break;
                }
                this.f4172a.m2568D(3);
                int m2584p = this.f4172a.m2584p();
                int i3 = m2584p + 10;
                if (metadata == null) {
                    byte[] bArr = new byte[i3];
                    System.arraycopy(this.f4172a.f6133a, 0, bArr, 0, 10);
                    c2003e.m1565e(bArr, 10, m2584p, false);
                    metadata = new C2088b(aVar).m1734c(bArr, i3);
                } else {
                    c2003e.m1561a(m2584p, false);
                }
                i2 += i3;
            } catch (EOFException unused) {
            }
        }
        c2003e.f3791f = 0;
        c2003e.m1561a(i2, false);
        return metadata;
    }
}
