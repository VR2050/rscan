package p505n;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Objects;
import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import kotlin.jvm.internal.Intrinsics;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p458k.C4371b0;
import p458k.C4373c0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4486w;
import p458k.C4487x;
import p458k.C4488y;
import p458k.C4489z;
import p458k.EnumC4377e0;
import p458k.InterfaceC4378f;
import p458k.InterfaceC4380g;
import p458k.p459p0.C4401c;
import p458k.p459p0.p462f.C4413c;
import p474l.AbstractC4749k;
import p474l.C4744f;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4764z;
import p505n.C5028w;

/* renamed from: n.q */
/* loaded from: classes3.dex */
public final class C5022q<T> implements InterfaceC4983d<T> {

    /* renamed from: c */
    public final C5029x f12839c;

    /* renamed from: e */
    public final Object[] f12840e;

    /* renamed from: f */
    public final InterfaceC4378f.a f12841f;

    /* renamed from: g */
    public final InterfaceC5013h<AbstractC4393m0, T> f12842g;

    /* renamed from: h */
    public volatile boolean f12843h;

    /* renamed from: i */
    @GuardedBy("this")
    @Nullable
    public InterfaceC4378f f12844i;

    /* renamed from: j */
    @GuardedBy("this")
    @Nullable
    public Throwable f12845j;

    /* renamed from: k */
    @GuardedBy("this")
    public boolean f12846k;

    /* renamed from: n.q$a */
    public class a implements InterfaceC4380g {

        /* renamed from: a */
        public final /* synthetic */ InterfaceC5011f f12847a;

        public a(InterfaceC5011f interfaceC5011f) {
            this.f12847a = interfaceC5011f;
        }

        @Override // p458k.InterfaceC4380g
        /* renamed from: a */
        public void mo195a(InterfaceC4378f interfaceC4378f, C4389k0 c4389k0) {
            try {
                try {
                    this.f12847a.mo276b(C5022q.this, C5022q.this.m5673d(c4389k0));
                } catch (Throwable th) {
                    C4984d0.m5668o(th);
                    th.printStackTrace();
                }
            } catch (Throwable th2) {
                C4984d0.m5668o(th2);
                try {
                    this.f12847a.mo275a(C5022q.this, th2);
                } catch (Throwable th3) {
                    C4984d0.m5668o(th3);
                    th3.printStackTrace();
                }
            }
        }

        @Override // p458k.InterfaceC4380g
        /* renamed from: b */
        public void mo196b(InterfaceC4378f interfaceC4378f, IOException iOException) {
            try {
                this.f12847a.mo275a(C5022q.this, iOException);
            } catch (Throwable th) {
                C4984d0.m5668o(th);
                th.printStackTrace();
            }
        }
    }

    /* renamed from: n.q$b */
    public static final class b extends AbstractC4393m0 {

        /* renamed from: e */
        public final AbstractC4393m0 f12849e;

        /* renamed from: f */
        public final InterfaceC4746h f12850f;

        /* renamed from: g */
        @Nullable
        public IOException f12851g;

        /* renamed from: n.q$b$a */
        public class a extends AbstractC4749k {
            public a(InterfaceC4764z interfaceC4764z) {
                super(interfaceC4764z);
            }

            @Override // p474l.AbstractC4749k, p474l.InterfaceC4764z
            /* renamed from: J */
            public long mo4924J(C4744f c4744f, long j2) {
                try {
                    return super.mo4924J(c4744f, j2);
                } catch (IOException e2) {
                    b.this.f12851g = e2;
                    throw e2;
                }
            }
        }

        public b(AbstractC4393m0 abstractC4393m0) {
            this.f12849e = abstractC4393m0;
            this.f12850f = C2354n.m2500o(new a(abstractC4393m0.mo4927k()));
        }

        @Override // p458k.AbstractC4393m0, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            this.f12849e.close();
        }

        @Override // p458k.AbstractC4393m0
        /* renamed from: d */
        public long mo4925d() {
            return this.f12849e.mo4925d();
        }

        @Override // p458k.AbstractC4393m0
        /* renamed from: e */
        public C4371b0 mo4926e() {
            return this.f12849e.mo4926e();
        }

        @Override // p458k.AbstractC4393m0
        /* renamed from: k */
        public InterfaceC4746h mo4927k() {
            return this.f12850f;
        }
    }

    /* renamed from: n.q$c */
    public static final class c extends AbstractC4393m0 {

        /* renamed from: e */
        @Nullable
        public final C4371b0 f12853e;

        /* renamed from: f */
        public final long f12854f;

        public c(@Nullable C4371b0 c4371b0, long j2) {
            this.f12853e = c4371b0;
            this.f12854f = j2;
        }

        @Override // p458k.AbstractC4393m0
        /* renamed from: d */
        public long mo4925d() {
            return this.f12854f;
        }

        @Override // p458k.AbstractC4393m0
        /* renamed from: e */
        public C4371b0 mo4926e() {
            return this.f12853e;
        }

        @Override // p458k.AbstractC4393m0
        /* renamed from: k */
        public InterfaceC4746h mo4927k() {
            throw new IllegalStateException("Cannot read raw response body of a converted body.");
        }
    }

    public C5022q(C5029x c5029x, Object[] objArr, InterfaceC4378f.a aVar, InterfaceC5013h<AbstractC4393m0, T> interfaceC5013h) {
        this.f12839c = c5029x;
        this.f12840e = objArr;
        this.f12841f = aVar;
        this.f12842g = interfaceC5013h;
    }

    /* renamed from: a */
    public final InterfaceC4378f m5671a() {
        C4489z m5299a;
        InterfaceC4378f.a aVar = this.f12841f;
        C5029x c5029x = this.f12839c;
        Object[] objArr = this.f12840e;
        AbstractC5026u<?>[] abstractC5026uArr = c5029x.f12930j;
        int length = objArr.length;
        if (length != abstractC5026uArr.length) {
            throw new IllegalArgumentException(C1499a.m580B(C1499a.m588J("Argument count (", length, ") doesn't match expected count ("), abstractC5026uArr.length, ChineseToPinyinResource.Field.RIGHT_BRACKET));
        }
        C5028w c5028w = new C5028w(c5029x.f12923c, c5029x.f12922b, c5029x.f12924d, c5029x.f12925e, c5029x.f12926f, c5029x.f12927g, c5029x.f12928h, c5029x.f12929i);
        if (c5029x.f12931k) {
            length--;
        }
        ArrayList arrayList = new ArrayList(length);
        for (int i2 = 0; i2 < length; i2++) {
            arrayList.add(objArr[i2]);
            abstractC5026uArr[i2].mo5674a(c5028w, objArr[i2]);
        }
        C4489z.a aVar2 = c5028w.f12911f;
        if (aVar2 != null) {
            m5299a = aVar2.m5299a();
        } else {
            C4489z c4489z = c5028w.f12909d;
            String link = c5028w.f12910e;
            Objects.requireNonNull(c4489z);
            Intrinsics.checkParameterIsNotNull(link, "link");
            C4489z.a m5296f = c4489z.m5296f(link);
            m5299a = m5296f != null ? m5296f.m5299a() : null;
            if (m5299a == null) {
                StringBuilder m586H = C1499a.m586H("Malformed URL. Base: ");
                m586H.append(c5028w.f12909d);
                m586H.append(", Relative: ");
                m586H.append(c5028w.f12910e);
                throw new IllegalArgumentException(m586H.toString());
            }
        }
        AbstractC4387j0 abstractC4387j0 = c5028w.f12918m;
        if (abstractC4387j0 == null) {
            C4486w.a aVar3 = c5028w.f12917l;
            if (aVar3 != null) {
                abstractC4387j0 = new C4486w(aVar3.f12029a, aVar3.f12030b);
            } else {
                C4373c0.a aVar4 = c5028w.f12916k;
                if (aVar4 != null) {
                    if (!(!aVar4.f11326c.isEmpty())) {
                        throw new IllegalStateException("Multipart body must have at least one part.".toString());
                    }
                    abstractC4387j0 = new C4373c0(aVar4.f11324a, aVar4.f11325b, C4401c.m5038w(aVar4.f11326c));
                } else if (c5028w.f12915j) {
                    abstractC4387j0 = AbstractC4387j0.m4986c(null, new byte[0]);
                }
            }
        }
        C4371b0 c4371b0 = c5028w.f12914i;
        if (c4371b0 != null) {
            if (abstractC4387j0 != null) {
                abstractC4387j0 = new C5028w.a(abstractC4387j0, c4371b0);
            } else {
                c5028w.f12913h.m5282a("Content-Type", c4371b0.f11310d);
            }
        }
        C4381g0.a aVar5 = c5028w.f12912g;
        aVar5.m4979i(m5299a);
        aVar5.m4974d(c5028w.f12913h.m5285d());
        aVar5.m4975e(c5028w.f12908c, abstractC4387j0);
        aVar5.m4977g(C5017l.class, new C5017l(c5029x.f12921a, arrayList));
        InterfaceC4378f mo4955a = aVar.mo4955a(aVar5.m4972b());
        Objects.requireNonNull(mo4955a, "Call.Factory returned null.");
        return mo4955a;
    }

    @Override // p505n.InterfaceC4983d
    /* renamed from: b */
    public boolean mo5650b() {
        boolean z = true;
        if (this.f12843h) {
            return true;
        }
        synchronized (this) {
            InterfaceC4378f interfaceC4378f = this.f12844i;
            if (interfaceC4378f == null || !interfaceC4378f.mo4962b()) {
                z = false;
            }
        }
        return z;
    }

    @GuardedBy("this")
    /* renamed from: c */
    public final InterfaceC4378f m5672c() {
        InterfaceC4378f interfaceC4378f = this.f12844i;
        if (interfaceC4378f != null) {
            return interfaceC4378f;
        }
        Throwable th = this.f12845j;
        if (th != null) {
            if (th instanceof IOException) {
                throw ((IOException) th);
            }
            if (th instanceof RuntimeException) {
                throw ((RuntimeException) th);
            }
            throw ((Error) th);
        }
        try {
            InterfaceC4378f m5671a = m5671a();
            this.f12844i = m5671a;
            return m5671a;
        } catch (IOException | Error | RuntimeException e2) {
            C4984d0.m5668o(e2);
            this.f12845j = e2;
            throw e2;
        }
    }

    @Override // p505n.InterfaceC4983d
    public void cancel() {
        InterfaceC4378f interfaceC4378f;
        this.f12843h = true;
        synchronized (this) {
            interfaceC4378f = this.f12844i;
        }
        if (interfaceC4378f != null) {
            interfaceC4378f.cancel();
        }
    }

    public Object clone() {
        return new C5022q(this.f12839c, this.f12840e, this.f12841f, this.f12842g);
    }

    /* renamed from: d */
    public C5030y<T> m5673d(C4389k0 response) {
        AbstractC4393m0 abstractC4393m0 = response.f11491k;
        Intrinsics.checkParameterIsNotNull(response, "response");
        C4381g0 c4381g0 = response.f11485e;
        EnumC4377e0 enumC4377e0 = response.f11486f;
        int i2 = response.f11488h;
        String str = response.f11487g;
        C4487x c4487x = response.f11489i;
        C4488y.a m5279c = response.f11490j.m5279c();
        C4389k0 c4389k0 = response.f11492l;
        C4389k0 c4389k02 = response.f11493m;
        C4389k0 c4389k03 = response.f11494n;
        long j2 = response.f11495o;
        long j3 = response.f11496p;
        C4413c c4413c = response.f11497q;
        c cVar = new c(abstractC4393m0.mo4926e(), abstractC4393m0.mo4925d());
        if (!(i2 >= 0)) {
            throw new IllegalStateException(C1499a.m626l("code < 0: ", i2).toString());
        }
        if (c4381g0 == null) {
            throw new IllegalStateException("request == null".toString());
        }
        if (enumC4377e0 == null) {
            throw new IllegalStateException("protocol == null".toString());
        }
        if (str == null) {
            throw new IllegalStateException("message == null".toString());
        }
        C4389k0 c4389k04 = new C4389k0(c4381g0, enumC4377e0, str, i2, c4487x, m5279c.m5285d(), cVar, c4389k0, c4389k02, c4389k03, j2, j3, c4413c);
        int i3 = c4389k04.f11488h;
        if (i3 < 200 || i3 >= 300) {
            try {
                AbstractC4393m0 m5654a = C4984d0.m5654a(abstractC4393m0);
                if (c4389k04.m4989e()) {
                    throw new IllegalArgumentException("rawResponse should not be successful response");
                }
                return new C5030y<>(c4389k04, null, m5654a);
            } finally {
                abstractC4393m0.close();
            }
        }
        if (i3 == 204 || i3 == 205) {
            abstractC4393m0.close();
            return C5030y.m5684b(null, c4389k04);
        }
        b bVar = new b(abstractC4393m0);
        try {
            return C5030y.m5684b(this.f12842g.convert(bVar), c4389k04);
        } catch (RuntimeException e2) {
            IOException iOException = bVar.f12851g;
            if (iOException == null) {
                throw e2;
            }
            throw iOException;
        }
    }

    @Override // p505n.InterfaceC4983d
    /* renamed from: e */
    public synchronized C4381g0 mo5651e() {
        try {
        } catch (IOException e2) {
            throw new RuntimeException("Unable to create request.", e2);
        }
        return m5672c().mo4963e();
    }

    @Override // p505n.InterfaceC4983d
    /* renamed from: o */
    public void mo5652o(InterfaceC5011f<T> interfaceC5011f) {
        InterfaceC4378f interfaceC4378f;
        Throwable th;
        synchronized (this) {
            if (this.f12846k) {
                throw new IllegalStateException("Already executed.");
            }
            this.f12846k = true;
            interfaceC4378f = this.f12844i;
            th = this.f12845j;
            if (interfaceC4378f == null && th == null) {
                try {
                    InterfaceC4378f m5671a = m5671a();
                    this.f12844i = m5671a;
                    interfaceC4378f = m5671a;
                } catch (Throwable th2) {
                    th = th2;
                    C4984d0.m5668o(th);
                    this.f12845j = th;
                }
            }
        }
        if (th != null) {
            interfaceC5011f.mo275a(this, th);
            return;
        }
        if (this.f12843h) {
            interfaceC4378f.cancel();
        }
        interfaceC4378f.mo4964k(new a(interfaceC5011f));
    }

    @Override // p505n.InterfaceC4983d
    /* renamed from: q */
    public InterfaceC4983d mo5653q() {
        return new C5022q(this.f12839c, this.f12840e, this.f12841f, this.f12842g);
    }
}
