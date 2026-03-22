package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.o1.c0 */
/* loaded from: classes.dex */
public final class C2285c0<T> implements C2281a0.e {

    /* renamed from: a */
    public final C2324p f5789a;

    /* renamed from: b */
    public final int f5790b;

    /* renamed from: c */
    public final C2287d0 f5791c;

    /* renamed from: d */
    public final a<? extends T> f5792d;

    /* renamed from: e */
    @Nullable
    public volatile T f5793e;

    /* renamed from: b.l.a.a.o1.c0$a */
    public interface a<T> {
        /* renamed from: a */
        T mo1900a(Uri uri, InputStream inputStream);
    }

    public C2285c0(InterfaceC2321m interfaceC2321m, Uri uri, int i2, a<? extends T> aVar) {
        C2324p c2324p = new C2324p(uri, 0L, 0L, -1L, null, 1);
        this.f5791c = new C2287d0(interfaceC2321m);
        this.f5789a = c2324p;
        this.f5790b = i2;
        this.f5792d = aVar;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: a */
    public final void mo1782a() {
        this.f5791c.f5797b = 0L;
        C2323o c2323o = new C2323o(this.f5791c, this.f5789a);
        try {
            if (!c2323o.f5930g) {
                c2323o.f5927c.open(c2323o.f5928e);
                c2323o.f5930g = true;
            }
            Uri uri = this.f5791c.getUri();
            Objects.requireNonNull(uri);
            this.f5793e = this.f5792d.mo1900a(uri, c2323o);
            try {
                c2323o.close();
            } catch (IOException unused) {
            }
        } finally {
            int i2 = C2344d0.f6035a;
            try {
                c2323o.close();
            } catch (IOException unused2) {
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: b */
    public final void mo1783b() {
    }
}
