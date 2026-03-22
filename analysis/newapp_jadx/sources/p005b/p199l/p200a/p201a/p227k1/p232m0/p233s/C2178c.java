package p005b.p199l.p200a.p201a.p227k1.p232m0.p233s;

import android.net.Uri;
import android.os.Handler;
import android.os.SystemClock;
import androidx.annotation.Nullable;
import androidx.work.WorkRequest;
import com.google.android.exoplayer2.Format;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p232m0.InterfaceC2166i;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2179d;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2180e;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.InterfaceC2184i;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p248o1.C2285c0;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.C2331w;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;

/* renamed from: b.l.a.a.k1.m0.s.c */
/* loaded from: classes.dex */
public final class C2178c implements InterfaceC2184i, C2281a0.b<C2285c0<AbstractC2181f>> {

    /* renamed from: c */
    public static final /* synthetic */ int f5011c = 0;

    /* renamed from: e */
    public final InterfaceC2166i f5012e;

    /* renamed from: f */
    public final InterfaceC2183h f5013f;

    /* renamed from: g */
    public final InterfaceC2334z f5014g;

    /* renamed from: k */
    @Nullable
    public C2285c0.a<AbstractC2181f> f5018k;

    /* renamed from: l */
    @Nullable
    public InterfaceC2203z.a f5019l;

    /* renamed from: m */
    @Nullable
    public C2281a0 f5020m;

    /* renamed from: n */
    @Nullable
    public Handler f5021n;

    /* renamed from: o */
    @Nullable
    public InterfaceC2184i.e f5022o;

    /* renamed from: p */
    @Nullable
    public C2179d f5023p;

    /* renamed from: q */
    @Nullable
    public Uri f5024q;

    /* renamed from: r */
    @Nullable
    public C2180e f5025r;

    /* renamed from: s */
    public boolean f5026s;

    /* renamed from: j */
    public final double f5017j = 3.5d;

    /* renamed from: i */
    public final List<InterfaceC2184i.b> f5016i = new ArrayList();

    /* renamed from: h */
    public final HashMap<Uri, a> f5015h = new HashMap<>();

    /* renamed from: t */
    public long f5027t = -9223372036854775807L;

    /* renamed from: b.l.a.a.k1.m0.s.c$a */
    public final class a implements C2281a0.b<C2285c0<AbstractC2181f>>, Runnable {

        /* renamed from: c */
        public final Uri f5028c;

        /* renamed from: e */
        public final C2281a0 f5029e = new C2281a0("DefaultHlsPlaylistTracker:MediaPlaylist");

        /* renamed from: f */
        public final C2285c0<AbstractC2181f> f5030f;

        /* renamed from: g */
        @Nullable
        public C2180e f5031g;

        /* renamed from: h */
        public long f5032h;

        /* renamed from: i */
        public long f5033i;

        /* renamed from: j */
        public long f5034j;

        /* renamed from: k */
        public long f5035k;

        /* renamed from: l */
        public boolean f5036l;

        /* renamed from: m */
        public IOException f5037m;

        public a(Uri uri) {
            this.f5028c = uri;
            this.f5030f = new C2285c0<>(C2178c.this.f5012e.mo1933a(4), uri, 4, C2178c.this.f5018k);
        }

        /* renamed from: a */
        public final boolean m1973a(long j2) {
            boolean z;
            this.f5035k = SystemClock.elapsedRealtime() + j2;
            if (!this.f5028c.equals(C2178c.this.f5024q)) {
                return false;
            }
            C2178c c2178c = C2178c.this;
            List<C2179d.b> list = c2178c.f5023p.f5041f;
            int size = list.size();
            long elapsedRealtime = SystemClock.elapsedRealtime();
            int i2 = 0;
            while (true) {
                if (i2 >= size) {
                    z = false;
                    break;
                }
                a aVar = c2178c.f5015h.get(list.get(i2).f5053a);
                if (elapsedRealtime > aVar.f5035k) {
                    c2178c.f5024q = aVar.f5028c;
                    aVar.m1974b();
                    z = true;
                    break;
                }
                i2++;
            }
            return !z;
        }

        /* renamed from: b */
        public void m1974b() {
            this.f5035k = 0L;
            if (this.f5036l || this.f5029e.m2183e() || this.f5029e.m2182d()) {
                return;
            }
            long elapsedRealtime = SystemClock.elapsedRealtime();
            long j2 = this.f5034j;
            if (elapsedRealtime >= j2) {
                m1975c();
            } else {
                this.f5036l = true;
                C2178c.this.f5021n.postDelayed(this, j2 - elapsedRealtime);
            }
        }

        /* renamed from: c */
        public final void m1975c() {
            C2281a0 c2281a0 = this.f5029e;
            C2285c0<AbstractC2181f> c2285c0 = this.f5030f;
            long m2186h = c2281a0.m2186h(c2285c0, this, ((C2331w) C2178c.this.f5014g).m2280b(c2285c0.f5790b));
            InterfaceC2203z.a aVar = C2178c.this.f5019l;
            C2285c0<AbstractC2181f> c2285c02 = this.f5030f;
            aVar.m2039o(c2285c02.f5789a, c2285c02.f5790b, m2186h);
        }

        /* JADX WARN: Removed duplicated region for block: B:15:0x0044  */
        /* JADX WARN: Removed duplicated region for block: B:22:0x0125  */
        /* JADX WARN: Removed duplicated region for block: B:58:0x029e  */
        /* JADX WARN: Removed duplicated region for block: B:68:0x02a1  */
        /* JADX WARN: Removed duplicated region for block: B:81:0x0232  */
        /* JADX WARN: Removed duplicated region for block: B:92:0x008b  */
        /* renamed from: d */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final void m1976d(p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2180e r50, long r51) {
            /*
                Method dump skipped, instructions count: 707
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2178c.a.m1976d(b.l.a.a.k1.m0.s.e, long):void");
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: k */
        public void mo1768k(C2285c0<AbstractC2181f> c2285c0, long j2, long j3, boolean z) {
            C2285c0<AbstractC2181f> c2285c02 = c2285c0;
            InterfaceC2203z.a aVar = C2178c.this.f5019l;
            C2324p c2324p = c2285c02.f5789a;
            C2287d0 c2287d0 = c2285c02.f5791c;
            aVar.m2030f(c2324p, c2287d0.f5798c, c2287d0.f5799d, 4, j2, j3, c2287d0.f5797b);
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: l */
        public void mo1769l(C2285c0<AbstractC2181f> c2285c0, long j2, long j3) {
            C2285c0<AbstractC2181f> c2285c02 = c2285c0;
            AbstractC2181f abstractC2181f = c2285c02.f5793e;
            if (!(abstractC2181f instanceof C2180e)) {
                this.f5037m = new C2205l0("Loaded playlist has unexpected type.");
                return;
            }
            m1976d((C2180e) abstractC2181f, j3);
            InterfaceC2203z.a aVar = C2178c.this.f5019l;
            C2324p c2324p = c2285c02.f5789a;
            C2287d0 c2287d0 = c2285c02.f5791c;
            aVar.m2033i(c2324p, c2287d0.f5798c, c2287d0.f5799d, 4, j2, j3, c2287d0.f5797b);
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f5036l = false;
            m1975c();
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: s */
        public C2281a0.c mo1775s(C2285c0<AbstractC2181f> c2285c0, long j2, long j3, IOException iOException, int i2) {
            C2281a0.c cVar;
            C2285c0<AbstractC2181f> c2285c02 = c2285c0;
            long m2279a = ((C2331w) C2178c.this.f5014g).m2279a(c2285c02.f5790b, j3, iOException, i2);
            boolean z = m2279a != -9223372036854775807L;
            boolean z2 = C2178c.m1968a(C2178c.this, this.f5028c, m2279a) || !z;
            if (z) {
                z2 |= m1973a(m2279a);
            }
            if (z2) {
                long m2281c = ((C2331w) C2178c.this.f5014g).m2281c(c2285c02.f5790b, j3, iOException, i2);
                cVar = m2281c != -9223372036854775807L ? C2281a0.m2179c(false, m2281c) : C2281a0.f5768b;
            } else {
                cVar = C2281a0.f5767a;
            }
            InterfaceC2203z.a aVar = C2178c.this.f5019l;
            C2324p c2324p = c2285c02.f5789a;
            C2287d0 c2287d0 = c2285c02.f5791c;
            aVar.m2036l(c2324p, c2287d0.f5798c, c2287d0.f5799d, 4, j2, j3, c2287d0.f5797b, iOException, !cVar.m2187a());
            return cVar;
        }
    }

    public C2178c(InterfaceC2166i interfaceC2166i, InterfaceC2334z interfaceC2334z, InterfaceC2183h interfaceC2183h) {
        this.f5012e = interfaceC2166i;
        this.f5013f = interfaceC2183h;
        this.f5014g = interfaceC2334z;
    }

    /* renamed from: a */
    public static boolean m1968a(C2178c c2178c, Uri uri, long j2) {
        int size = c2178c.f5016i.size();
        boolean z = false;
        for (int i2 = 0; i2 < size; i2++) {
            z |= !c2178c.f5016i.get(i2).mo1950h(uri, j2);
        }
        return z;
    }

    /* renamed from: b */
    public static C2180e.a m1969b(C2180e c2180e, C2180e c2180e2) {
        int i2 = (int) (c2180e2.f5064i - c2180e.f5064i);
        List<C2180e.a> list = c2180e.f5070o;
        if (i2 < list.size()) {
            return list.get(i2);
        }
        return null;
    }

    @Nullable
    /* renamed from: c */
    public C2180e m1970c(Uri uri, boolean z) {
        C2180e c2180e;
        C2180e c2180e2 = this.f5015h.get(uri).f5031g;
        if (c2180e2 != null && z && !uri.equals(this.f5024q)) {
            List<C2179d.b> list = this.f5023p.f5041f;
            boolean z2 = false;
            int i2 = 0;
            while (true) {
                if (i2 >= list.size()) {
                    break;
                }
                if (uri.equals(list.get(i2).f5053a)) {
                    z2 = true;
                    break;
                }
                i2++;
            }
            if (z2 && ((c2180e = this.f5025r) == null || !c2180e.f5067l)) {
                this.f5024q = uri;
                this.f5015h.get(uri).m1974b();
            }
        }
        return c2180e2;
    }

    /* renamed from: d */
    public boolean m1971d(Uri uri) {
        int i2;
        a aVar = this.f5015h.get(uri);
        if (aVar.f5031g == null) {
            return false;
        }
        long elapsedRealtime = SystemClock.elapsedRealtime();
        long max = Math.max(WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS, C2399v.m2669b(aVar.f5031g.f5071p));
        C2180e c2180e = aVar.f5031g;
        return c2180e.f5067l || (i2 = c2180e.f5059d) == 2 || i2 == 1 || aVar.f5032h + max > elapsedRealtime;
    }

    /* renamed from: e */
    public void m1972e(Uri uri) {
        a aVar = this.f5015h.get(uri);
        aVar.f5029e.m2184f(Integer.MIN_VALUE);
        IOException iOException = aVar.f5037m;
        if (iOException != null) {
            throw iOException;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: k */
    public void mo1768k(C2285c0<AbstractC2181f> c2285c0, long j2, long j3, boolean z) {
        C2285c0<AbstractC2181f> c2285c02 = c2285c0;
        InterfaceC2203z.a aVar = this.f5019l;
        C2324p c2324p = c2285c02.f5789a;
        C2287d0 c2287d0 = c2285c02.f5791c;
        aVar.m2030f(c2324p, c2287d0.f5798c, c2287d0.f5799d, 4, j2, j3, c2287d0.f5797b);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: l */
    public void mo1769l(C2285c0<AbstractC2181f> c2285c0, long j2, long j3) {
        C2179d c2179d;
        C2285c0<AbstractC2181f> c2285c02 = c2285c0;
        AbstractC2181f abstractC2181f = c2285c02.f5793e;
        boolean z = abstractC2181f instanceof C2180e;
        if (z) {
            String str = abstractC2181f.f5083a;
            C2179d c2179d2 = C2179d.f5039d;
            c2179d = new C2179d("", Collections.emptyList(), Collections.singletonList(new C2179d.b(Uri.parse(str), Format.m4025B("0", null, "application/x-mpegURL", null, null, -1, 0, 0, null), null, null, null, null)), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), null, null, false, Collections.emptyMap(), Collections.emptyList());
        } else {
            c2179d = (C2179d) abstractC2181f;
        }
        this.f5023p = c2179d;
        Objects.requireNonNull((C2177b) this.f5013f);
        this.f5018k = new C2182g(c2179d);
        this.f5024q = c2179d.f5041f.get(0).f5053a;
        List<Uri> list = c2179d.f5040e;
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            Uri uri = list.get(i2);
            this.f5015h.put(uri, new a(uri));
        }
        a aVar = this.f5015h.get(this.f5024q);
        if (z) {
            aVar.m1976d((C2180e) abstractC2181f, j3);
        } else {
            aVar.m1974b();
        }
        InterfaceC2203z.a aVar2 = this.f5019l;
        C2324p c2324p = c2285c02.f5789a;
        C2287d0 c2287d0 = c2285c02.f5791c;
        aVar2.m2033i(c2324p, c2287d0.f5798c, c2287d0.f5799d, 4, j2, j3, c2287d0.f5797b);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: s */
    public C2281a0.c mo1775s(C2285c0<AbstractC2181f> c2285c0, long j2, long j3, IOException iOException, int i2) {
        C2285c0<AbstractC2181f> c2285c02 = c2285c0;
        long m2281c = ((C2331w) this.f5014g).m2281c(c2285c02.f5790b, j3, iOException, i2);
        boolean z = m2281c == -9223372036854775807L;
        InterfaceC2203z.a aVar = this.f5019l;
        C2324p c2324p = c2285c02.f5789a;
        C2287d0 c2287d0 = c2285c02.f5791c;
        aVar.m2036l(c2324p, c2287d0.f5798c, c2287d0.f5799d, 4, j2, j3, c2287d0.f5797b, iOException, z);
        return z ? C2281a0.f5768b : C2281a0.m2179c(false, m2281c);
    }
}
