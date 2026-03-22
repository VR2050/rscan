package p005b.p199l.p200a.p201a.p227k1.p230l0;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.emsg.EventMessage;
import com.google.android.exoplayer2.source.dash.DashMediaSource;
import java.nio.charset.Charset;
import java.util.TreeMap;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p220h1.C2081d;
import p005b.p199l.p200a.p201a.p220h1.p221g.C2084a;
import p005b.p199l.p200a.p201a.p227k1.C2103c0;
import p005b.p199l.p200a.p201a.p227k1.C2105d0;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2145b;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.k1.l0.j */
/* loaded from: classes.dex */
public final class C2143j implements Handler.Callback {

    /* renamed from: c */
    public final InterfaceC2288e f4758c;

    /* renamed from: e */
    public final b f4759e;

    /* renamed from: f */
    public final C2084a f4760f;

    /* renamed from: g */
    public final Handler f4761g;

    /* renamed from: h */
    public final TreeMap<Long, Long> f4762h = new TreeMap<>();

    /* renamed from: i */
    public C2145b f4763i;

    /* renamed from: j */
    public long f4764j;

    /* renamed from: k */
    public long f4765k;

    /* renamed from: l */
    public long f4766l;

    /* renamed from: m */
    public boolean f4767m;

    /* renamed from: n */
    public boolean f4768n;

    /* renamed from: b.l.a.a.k1.l0.j$a */
    public static final class a {

        /* renamed from: a */
        public final long f4769a;

        /* renamed from: b */
        public final long f4770b;

        public a(long j2, long j3) {
            this.f4769a = j2;
            this.f4770b = j3;
        }
    }

    /* renamed from: b.l.a.a.k1.l0.j$b */
    public interface b {
    }

    /* renamed from: b.l.a.a.k1.l0.j$c */
    public final class c implements InterfaceC2052s {

        /* renamed from: a */
        public final C2105d0 f4771a;

        /* renamed from: b */
        public final C1964f0 f4772b = new C1964f0();

        /* renamed from: c */
        public final C2081d f4773c = new C2081d();

        public c(InterfaceC2288e interfaceC2288e) {
            this.f4771a = new C2105d0(interfaceC2288e, InterfaceC1954e.f3383a);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: a */
        public int mo1612a(C2003e c2003e, int i2, boolean z) {
            return this.f4771a.mo1612a(c2003e, i2, z);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: b */
        public void mo1613b(C2360t c2360t, int i2) {
            this.f4771a.mo1613b(c2360t, i2);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: c */
        public void mo1614c(long j2, int i2, int i3, int i4, @Nullable InterfaceC2052s.a aVar) {
            long m1811g;
            C2081d c2081d;
            long j3;
            this.f4771a.mo1614c(j2, i2, i3, i4, aVar);
            while (true) {
                boolean z = false;
                if (!this.f4771a.m1825u(false)) {
                    break;
                }
                this.f4773c.clear();
                if (this.f4771a.m1803A(this.f4772b, this.f4773c, false, false, 0L) == -4) {
                    this.f4773c.m1382g();
                    c2081d = this.f4773c;
                } else {
                    c2081d = null;
                }
                if (c2081d != null) {
                    long j4 = c2081d.f3307f;
                    EventMessage eventMessage = (EventMessage) C2143j.this.f4760f.mo1705a(c2081d).f9273c[0];
                    String str = eventMessage.f9276f;
                    String str2 = eventMessage.f9277g;
                    if ("urn:mpeg:dash:event:2012".equals(str) && ("1".equals(str2) || "2".equals(str2) || "3".equals(str2))) {
                        z = true;
                    }
                    if (z) {
                        try {
                            byte[] bArr = eventMessage.f9280j;
                            int i5 = C2344d0.f6035a;
                            j3 = C2344d0.m2311C(new String(bArr, Charset.forName("UTF-8")));
                        } catch (C2205l0 unused) {
                            j3 = -9223372036854775807L;
                        }
                        if (j3 != -9223372036854775807L) {
                            a aVar2 = new a(j4, j3);
                            Handler handler = C2143j.this.f4761g;
                            handler.sendMessage(handler.obtainMessage(1, aVar2));
                        }
                    }
                }
            }
            C2105d0 c2105d0 = this.f4771a;
            C2103c0 c2103c0 = c2105d0.f4544a;
            synchronized (c2105d0) {
                int i6 = c2105d0.f4561r;
                m1811g = i6 == 0 ? -1L : c2105d0.m1811g(i6);
            }
            c2103c0.m1797b(m1811g);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: d */
        public void mo1615d(Format format) {
            this.f4771a.mo1615d(format);
        }
    }

    public C2143j(C2145b c2145b, b bVar, InterfaceC2288e interfaceC2288e) {
        this.f4763i = c2145b;
        this.f4759e = bVar;
        this.f4758c = interfaceC2288e;
        int i2 = C2344d0.f6035a;
        Looper myLooper = Looper.myLooper();
        this.f4761g = new Handler(myLooper == null ? Looper.getMainLooper() : myLooper, this);
        this.f4760f = new C2084a();
        this.f4765k = -9223372036854775807L;
        this.f4766l = -9223372036854775807L;
    }

    /* renamed from: a */
    public final void m1886a() {
        long j2 = this.f4766l;
        if (j2 == -9223372036854775807L || j2 != this.f4765k) {
            this.f4767m = true;
            this.f4766l = this.f4765k;
            DashMediaSource dashMediaSource = DashMediaSource.this;
            dashMediaSource.f9404E.removeCallbacks(dashMediaSource.f9429w);
            dashMediaSource.m4064v();
        }
    }

    @Override // android.os.Handler.Callback
    public boolean handleMessage(Message message) {
        if (this.f4768n) {
            return true;
        }
        if (message.what != 1) {
            return false;
        }
        a aVar = (a) message.obj;
        long j2 = aVar.f4769a;
        long j3 = aVar.f4770b;
        Long l2 = this.f4762h.get(Long.valueOf(j3));
        if (l2 == null) {
            this.f4762h.put(Long.valueOf(j3), Long.valueOf(j2));
        } else if (l2.longValue() > j2) {
            this.f4762h.put(Long.valueOf(j3), Long.valueOf(j2));
        }
        return true;
    }
}
