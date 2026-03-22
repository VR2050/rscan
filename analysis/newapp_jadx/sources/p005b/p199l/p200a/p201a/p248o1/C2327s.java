package p005b.p199l.p200a.p201a.p248o1;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.upstream.RawResourceDataSource;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.s */
/* loaded from: classes.dex */
public final class C2327s implements InterfaceC2321m {

    /* renamed from: a */
    public final Context f5976a;

    /* renamed from: b */
    public final List<InterfaceC2291f0> f5977b;

    /* renamed from: c */
    public final InterfaceC2321m f5978c;

    /* renamed from: d */
    @Nullable
    public InterfaceC2321m f5979d;

    /* renamed from: e */
    @Nullable
    public InterfaceC2321m f5980e;

    /* renamed from: f */
    @Nullable
    public InterfaceC2321m f5981f;

    /* renamed from: g */
    @Nullable
    public InterfaceC2321m f5982g;

    /* renamed from: h */
    @Nullable
    public InterfaceC2321m f5983h;

    /* renamed from: i */
    @Nullable
    public InterfaceC2321m f5984i;

    /* renamed from: j */
    @Nullable
    public InterfaceC2321m f5985j;

    /* renamed from: k */
    @Nullable
    public InterfaceC2321m f5986k;

    public C2327s(Context context, InterfaceC2321m interfaceC2321m) {
        this.f5976a = context.getApplicationContext();
        Objects.requireNonNull(interfaceC2321m);
        this.f5978c = interfaceC2321m;
        this.f5977b = new ArrayList();
    }

    /* renamed from: a */
    public final void m2278a(InterfaceC2321m interfaceC2321m) {
        for (int i2 = 0; i2 < this.f5977b.size(); i2++) {
            interfaceC2321m.addTransferListener(this.f5977b.get(i2));
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void addTransferListener(InterfaceC2291f0 interfaceC2291f0) {
        this.f5978c.addTransferListener(interfaceC2291f0);
        this.f5977b.add(interfaceC2291f0);
        InterfaceC2321m interfaceC2321m = this.f5979d;
        if (interfaceC2321m != null) {
            interfaceC2321m.addTransferListener(interfaceC2291f0);
        }
        InterfaceC2321m interfaceC2321m2 = this.f5980e;
        if (interfaceC2321m2 != null) {
            interfaceC2321m2.addTransferListener(interfaceC2291f0);
        }
        InterfaceC2321m interfaceC2321m3 = this.f5981f;
        if (interfaceC2321m3 != null) {
            interfaceC2321m3.addTransferListener(interfaceC2291f0);
        }
        InterfaceC2321m interfaceC2321m4 = this.f5982g;
        if (interfaceC2321m4 != null) {
            interfaceC2321m4.addTransferListener(interfaceC2291f0);
        }
        InterfaceC2321m interfaceC2321m5 = this.f5983h;
        if (interfaceC2321m5 != null) {
            interfaceC2321m5.addTransferListener(interfaceC2291f0);
        }
        InterfaceC2321m interfaceC2321m6 = this.f5984i;
        if (interfaceC2321m6 != null) {
            interfaceC2321m6.addTransferListener(interfaceC2291f0);
        }
        InterfaceC2321m interfaceC2321m7 = this.f5985j;
        if (interfaceC2321m7 != null) {
            interfaceC2321m7.addTransferListener(interfaceC2291f0);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        InterfaceC2321m interfaceC2321m = this.f5986k;
        if (interfaceC2321m != null) {
            try {
                interfaceC2321m.close();
            } finally {
                this.f5986k = null;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public Map<String, List<String>> getResponseHeaders() {
        InterfaceC2321m interfaceC2321m = this.f5986k;
        return interfaceC2321m == null ? Collections.emptyMap() : interfaceC2321m.getResponseHeaders();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        InterfaceC2321m interfaceC2321m = this.f5986k;
        if (interfaceC2321m == null) {
            return null;
        }
        return interfaceC2321m.getUri();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        boolean z = true;
        C4195m.m4771I(this.f5986k == null);
        String scheme = c2324p.f5933a.getScheme();
        Uri uri = c2324p.f5933a;
        int i2 = C2344d0.f6035a;
        String scheme2 = uri.getScheme();
        if (!TextUtils.isEmpty(scheme2) && !"file".equals(scheme2)) {
            z = false;
        }
        if (z) {
            String path = c2324p.f5933a.getPath();
            if (path == null || !path.startsWith("/android_asset/")) {
                if (this.f5979d == null) {
                    C2332x c2332x = new C2332x();
                    this.f5979d = c2332x;
                    m2278a(c2332x);
                }
                this.f5986k = this.f5979d;
            } else {
                if (this.f5980e == null) {
                    C2290f c2290f = new C2290f(this.f5976a);
                    this.f5980e = c2290f;
                    m2278a(c2290f);
                }
                this.f5986k = this.f5980e;
            }
        } else if ("asset".equals(scheme)) {
            if (this.f5980e == null) {
                C2290f c2290f2 = new C2290f(this.f5976a);
                this.f5980e = c2290f2;
                m2278a(c2290f2);
            }
            this.f5986k = this.f5980e;
        } else if ("content".equals(scheme)) {
            if (this.f5981f == null) {
                C2317i c2317i = new C2317i(this.f5976a);
                this.f5981f = c2317i;
                m2278a(c2317i);
            }
            this.f5986k = this.f5981f;
        } else if ("rtmp".equals(scheme)) {
            if (this.f5982g == null) {
                try {
                    InterfaceC2321m interfaceC2321m = (InterfaceC2321m) Class.forName("b.l.a.a.e1.a.a").getConstructor(new Class[0]).newInstance(new Object[0]);
                    this.f5982g = interfaceC2321m;
                    m2278a(interfaceC2321m);
                } catch (ClassNotFoundException unused) {
                } catch (Exception e2) {
                    throw new RuntimeException("Error instantiating RTMP extension", e2);
                }
                if (this.f5982g == null) {
                    this.f5982g = this.f5978c;
                }
            }
            this.f5986k = this.f5982g;
        } else if ("udp".equals(scheme)) {
            if (this.f5983h == null) {
                C2293g0 c2293g0 = new C2293g0();
                this.f5983h = c2293g0;
                m2278a(c2293g0);
            }
            this.f5986k = this.f5983h;
        } else if ("data".equals(scheme)) {
            if (this.f5984i == null) {
                C2318j c2318j = new C2318j();
                this.f5984i = c2318j;
                m2278a(c2318j);
            }
            this.f5986k = this.f5984i;
        } else if ("rawresource".equals(scheme)) {
            if (this.f5985j == null) {
                RawResourceDataSource rawResourceDataSource = new RawResourceDataSource(this.f5976a);
                this.f5985j = rawResourceDataSource;
                m2278a(rawResourceDataSource);
            }
            this.f5986k = this.f5985j;
        } else {
            this.f5986k = this.f5978c;
        }
        return this.f5986k.open(c2324p);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        InterfaceC2321m interfaceC2321m = this.f5986k;
        Objects.requireNonNull(interfaceC2321m);
        return interfaceC2321m.read(bArr, i2, i3);
    }
}
