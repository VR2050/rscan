package p005b.p199l.p200a.p201a.p227k1.p229k0;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.io.IOException;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2123e;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.k0.k */
/* loaded from: classes.dex */
public final class C2129k extends AbstractC2122d {

    /* renamed from: i */
    public static final C2049p f4685i = new C2049p();

    /* renamed from: j */
    public final C2123e f4686j;

    /* renamed from: k */
    public C2123e.b f4687k;

    /* renamed from: l */
    public long f4688l;

    /* renamed from: m */
    public volatile boolean f4689m;

    public C2129k(InterfaceC2321m interfaceC2321m, C2324p c2324p, Format format, int i2, @Nullable Object obj, C2123e c2123e) {
        super(interfaceC2321m, c2324p, 2, format, i2, obj, -9223372036854775807L, -9223372036854775807L);
        this.f4686j = c2123e;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: a */
    public void mo1782a() {
        if (this.f4688l == 0) {
            this.f4686j.m1841b(this.f4687k, -9223372036854775807L, -9223372036854775807L);
        }
        try {
            C2324p m2268c = this.f4623a.m2268c(this.f4688l);
            C2287d0 c2287d0 = this.f4630h;
            C2003e c2003e = new C2003e(c2287d0, m2268c.f5937e, c2287d0.open(m2268c));
            try {
                InterfaceC2041h interfaceC2041h = this.f4686j.f4631c;
                int i2 = 0;
                while (i2 == 0 && !this.f4689m) {
                    i2 = interfaceC2041h.mo1479d(c2003e, f4685i);
                }
                C4195m.m4771I(i2 != 1);
                if (r0 != null) {
                    try {
                        this.f4630h.close();
                    } catch (IOException unused) {
                    }
                }
            } finally {
                this.f4688l = c2003e.f3789d - this.f4623a.f5937e;
            }
        } finally {
            C2287d0 c2287d02 = this.f4630h;
            int i3 = C2344d0.f6035a;
            if (c2287d02 != null) {
                try {
                    c2287d02.close();
                } catch (IOException unused2) {
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: b */
    public void mo1783b() {
        this.f4689m = true;
    }
}
