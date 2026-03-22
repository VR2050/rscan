package p005b.p199l.p200a.p201a;

import p005b.p199l.p200a.p201a.p248o1.C2325q;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.y */
/* loaded from: classes.dex */
public class C2405y implements InterfaceC2077h0 {

    /* renamed from: a */
    public final C2325q f6383a;

    /* renamed from: b */
    public final long f6384b;

    /* renamed from: c */
    public final long f6385c;

    /* renamed from: d */
    public final long f6386d;

    /* renamed from: e */
    public final long f6387e;

    /* renamed from: f */
    public final long f6388f;

    /* renamed from: g */
    public final int f6389g;

    /* renamed from: h */
    public final boolean f6390h;

    /* renamed from: i */
    public final long f6391i;

    /* renamed from: j */
    public int f6392j;

    /* renamed from: k */
    public boolean f6393k;

    /* renamed from: l */
    public boolean f6394l;

    public C2405y() {
        C2325q c2325q = new C2325q(true, 65536);
        m2700a(2500, 0, "bufferForPlaybackMs", "0");
        m2700a(5000, 0, "bufferForPlaybackAfterRebufferMs", "0");
        m2700a(15000, 2500, "minBufferAudioMs", "bufferForPlaybackMs");
        m2700a(50000, 2500, "minBufferVideoMs", "bufferForPlaybackMs");
        m2700a(15000, 5000, "minBufferAudioMs", "bufferForPlaybackAfterRebufferMs");
        m2700a(50000, 5000, "minBufferVideoMs", "bufferForPlaybackAfterRebufferMs");
        m2700a(50000, 15000, "maxBufferMs", "minBufferAudioMs");
        m2700a(50000, 50000, "maxBufferMs", "minBufferVideoMs");
        m2700a(0, 0, "backBufferDurationMs", "0");
        this.f6383a = c2325q;
        this.f6384b = C2399v.m2668a(15000);
        long j2 = 50000;
        this.f6385c = C2399v.m2668a(j2);
        this.f6386d = C2399v.m2668a(j2);
        this.f6387e = C2399v.m2668a(2500);
        this.f6388f = C2399v.m2668a(5000);
        this.f6389g = -1;
        this.f6390h = true;
        this.f6391i = C2399v.m2668a(0);
    }

    /* renamed from: a */
    public static void m2700a(int i2, int i3, String str, String str2) {
        C4195m.m4761D(i2 >= i3, str + " cannot be less than " + str2);
    }

    /* renamed from: b */
    public final void m2701b(boolean z) {
        this.f6392j = 0;
        this.f6393k = false;
        if (z) {
            C2325q c2325q = this.f6383a;
            synchronized (c2325q) {
                if (c2325q.f5942a) {
                    c2325q.m2271b(0);
                }
            }
        }
    }
}
