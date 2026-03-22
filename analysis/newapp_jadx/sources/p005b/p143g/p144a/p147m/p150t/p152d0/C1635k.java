package p005b.p143g.p144a.p147m.p150t.p152d0;

import androidx.annotation.NonNull;
import androidx.core.util.Pools;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import org.conscrypt.EvpMdRef;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p170s.C1804f;
import p005b.p143g.p144a.p170s.C1807i;
import p005b.p143g.p144a.p170s.p171j.AbstractC1811d;
import p005b.p143g.p144a.p170s.p171j.C1808a;

/* renamed from: b.g.a.m.t.d0.k */
/* loaded from: classes.dex */
public class C1635k {

    /* renamed from: a */
    public final C1804f<InterfaceC1579k, String> f2131a = new C1804f<>(1000);

    /* renamed from: b */
    public final Pools.Pool<b> f2132b = C1808a.m1153a(10, new a(this));

    /* renamed from: b.g.a.m.t.d0.k$a */
    public class a implements C1808a.b<b> {
        public a(C1635k c1635k) {
        }

        @Override // p005b.p143g.p144a.p170s.p171j.C1808a.b
        public b create() {
            try {
                return new b(MessageDigest.getInstance(EvpMdRef.SHA256.JCA_NAME));
            } catch (NoSuchAlgorithmException e2) {
                throw new RuntimeException(e2);
            }
        }
    }

    /* renamed from: b.g.a.m.t.d0.k$b */
    public static final class b implements C1808a.d {

        /* renamed from: c */
        public final MessageDigest f2133c;

        /* renamed from: e */
        public final AbstractC1811d f2134e = new AbstractC1811d.b();

        public b(MessageDigest messageDigest) {
            this.f2133c = messageDigest;
        }

        @Override // p005b.p143g.p144a.p170s.p171j.C1808a.d
        @NonNull
        /* renamed from: b */
        public AbstractC1811d mo903b() {
            return this.f2134e;
        }
    }

    /* renamed from: a */
    public String m902a(InterfaceC1579k interfaceC1579k) {
        String m1139a;
        synchronized (this.f2131a) {
            m1139a = this.f2131a.m1139a(interfaceC1579k);
        }
        if (m1139a == null) {
            b acquire = this.f2132b.acquire();
            Objects.requireNonNull(acquire, "Argument must not be null");
            b bVar = acquire;
            try {
                interfaceC1579k.updateDiskCacheKey(bVar.f2133c);
                byte[] digest = bVar.f2133c.digest();
                char[] cArr = C1807i.f2768b;
                synchronized (cArr) {
                    for (int i2 = 0; i2 < digest.length; i2++) {
                        int i3 = digest[i2] & 255;
                        int i4 = i2 * 2;
                        char[] cArr2 = C1807i.f2767a;
                        cArr[i4] = cArr2[i3 >>> 4];
                        cArr[i4 + 1] = cArr2[i3 & 15];
                    }
                    m1139a = new String(cArr);
                }
            } finally {
                this.f2132b.release(bVar);
            }
        }
        synchronized (this.f2131a) {
            this.f2131a.m1140d(interfaceC1579k, m1139a);
        }
        return m1139a;
    }
}
