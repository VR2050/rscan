package p005b.p199l.p200a.p201a.p202a1;

import android.media.AudioTrack;
import android.os.ConditionVariable;
import android.os.Handler;
import android.os.SystemClock;
import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.p202a1.C1924p;
import p005b.p199l.p200a.p201a.p202a1.C1931w;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1922n;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.a.a.a1.t */
/* loaded from: classes.dex */
public final class C1928t implements InterfaceC1922n {

    /* renamed from: A */
    public long f3131A;

    /* renamed from: B */
    public float f3132B;

    /* renamed from: C */
    public InterfaceC1920l[] f3133C;

    /* renamed from: D */
    public ByteBuffer[] f3134D;

    /* renamed from: E */
    @Nullable
    public ByteBuffer f3135E;

    /* renamed from: F */
    @Nullable
    public ByteBuffer f3136F;

    /* renamed from: G */
    public byte[] f3137G;

    /* renamed from: H */
    public int f3138H;

    /* renamed from: I */
    public int f3139I;

    /* renamed from: J */
    public boolean f3140J;

    /* renamed from: K */
    public boolean f3141K;

    /* renamed from: L */
    public boolean f3142L;

    /* renamed from: M */
    public int f3143M;

    /* renamed from: N */
    public C1925q f3144N;

    /* renamed from: O */
    public boolean f3145O;

    /* renamed from: P */
    public long f3146P;

    /* renamed from: a */
    @Nullable
    public final C1918j f3147a;

    /* renamed from: b */
    public final b f3148b;

    /* renamed from: c */
    public final C1927s f3149c;

    /* renamed from: d */
    public final C1910b0 f3150d;

    /* renamed from: e */
    public final InterfaceC1920l[] f3151e;

    /* renamed from: f */
    public final InterfaceC1920l[] f3152f;

    /* renamed from: g */
    public final ConditionVariable f3153g;

    /* renamed from: h */
    public final C1924p f3154h;

    /* renamed from: i */
    public final ArrayDeque<e> f3155i;

    /* renamed from: j */
    @Nullable
    public InterfaceC1922n.c f3156j;

    /* renamed from: k */
    @Nullable
    public c f3157k;

    /* renamed from: l */
    public c f3158l;

    /* renamed from: m */
    public AudioTrack f3159m;

    /* renamed from: n */
    public C1917i f3160n;

    /* renamed from: o */
    @Nullable
    public C2262n0 f3161o;

    /* renamed from: p */
    public C2262n0 f3162p;

    /* renamed from: q */
    public long f3163q;

    /* renamed from: r */
    public long f3164r;

    /* renamed from: s */
    @Nullable
    public ByteBuffer f3165s;

    /* renamed from: t */
    public int f3166t;

    /* renamed from: u */
    public long f3167u;

    /* renamed from: v */
    public long f3168v;

    /* renamed from: w */
    public long f3169w;

    /* renamed from: x */
    public long f3170x;

    /* renamed from: y */
    public int f3171y;

    /* renamed from: z */
    public int f3172z;

    /* renamed from: b.l.a.a.a1.t$a */
    public class a extends Thread {

        /* renamed from: c */
        public final /* synthetic */ AudioTrack f3173c;

        public a(AudioTrack audioTrack) {
            this.f3173c = audioTrack;
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            try {
                this.f3173c.flush();
                this.f3173c.release();
            } finally {
                C1928t.this.f3153g.open();
            }
        }
    }

    /* renamed from: b.l.a.a.a1.t$b */
    public interface b {
        /* renamed from: a */
        C2262n0 mo1296a(C2262n0 c2262n0);

        /* renamed from: b */
        long mo1297b(long j2);

        /* renamed from: c */
        long mo1298c();
    }

    /* renamed from: b.l.a.a.a1.t$c */
    public static final class c {

        /* renamed from: a */
        public final boolean f3175a;

        /* renamed from: b */
        public final int f3176b;

        /* renamed from: c */
        public final int f3177c;

        /* renamed from: d */
        public final int f3178d;

        /* renamed from: e */
        public final int f3179e;

        /* renamed from: f */
        public final int f3180f;

        /* renamed from: g */
        public final int f3181g;

        /* renamed from: h */
        public final int f3182h;

        /* renamed from: i */
        public final boolean f3183i;

        /* renamed from: j */
        public final boolean f3184j;

        /* renamed from: k */
        public final InterfaceC1920l[] f3185k;

        public c(boolean z, int i2, int i3, int i4, int i5, int i6, int i7, int i8, boolean z2, boolean z3, InterfaceC1920l[] interfaceC1920lArr) {
            int i9;
            int i10;
            this.f3175a = z;
            this.f3176b = i2;
            this.f3177c = i3;
            this.f3178d = i4;
            this.f3179e = i5;
            this.f3180f = i6;
            this.f3181g = i7;
            if (i8 == 0) {
                if (z) {
                    int minBufferSize = AudioTrack.getMinBufferSize(i5, i6, i7);
                    C4195m.m4771I(minBufferSize != -2);
                    long j2 = i5;
                    i10 = C2344d0.m2329g(minBufferSize * 4, ((int) ((250000 * j2) / 1000000)) * i4, (int) Math.max(minBufferSize, ((j2 * 750000) / 1000000) * i4));
                } else {
                    if (i7 != 5) {
                        if (i7 != 6) {
                            if (i7 == 7) {
                                i9 = 192000;
                            } else if (i7 == 8) {
                                i9 = 2250000;
                            } else if (i7 == 14) {
                                i9 = 3062500;
                            } else if (i7 == 17) {
                                i9 = 336000;
                            } else if (i7 != 18) {
                                throw new IllegalArgumentException();
                            }
                        }
                        i9 = 768000;
                    } else {
                        i9 = 80000;
                    }
                    i10 = (int) (((i7 == 5 ? i9 * 2 : i9) * 250000) / 1000000);
                }
                i8 = i10;
            }
            this.f3182h = i8;
            this.f3183i = z2;
            this.f3184j = z3;
            this.f3185k = interfaceC1920lArr;
        }

        /* renamed from: a */
        public long m1299a(long j2) {
            return (j2 * 1000000) / this.f3179e;
        }
    }

    /* renamed from: b.l.a.a.a1.t$d */
    public static class d implements b {

        /* renamed from: a */
        public final InterfaceC1920l[] f3186a;

        /* renamed from: b */
        public final C1933y f3187b;

        /* renamed from: c */
        public final C1908a0 f3188c;

        public d(InterfaceC1920l... interfaceC1920lArr) {
            InterfaceC1920l[] interfaceC1920lArr2 = new InterfaceC1920l[interfaceC1920lArr.length + 2];
            this.f3186a = interfaceC1920lArr2;
            System.arraycopy(interfaceC1920lArr, 0, interfaceC1920lArr2, 0, interfaceC1920lArr.length);
            C1933y c1933y = new C1933y();
            this.f3187b = c1933y;
            C1908a0 c1908a0 = new C1908a0();
            this.f3188c = c1908a0;
            interfaceC1920lArr2[interfaceC1920lArr.length] = c1933y;
            interfaceC1920lArr2[interfaceC1920lArr.length + 1] = c1908a0;
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.C1928t.b
        /* renamed from: a */
        public C2262n0 mo1296a(C2262n0 c2262n0) {
            this.f3187b.f3214j = c2262n0.f5671d;
            C1908a0 c1908a0 = this.f3188c;
            float f2 = c2262n0.f5669b;
            Objects.requireNonNull(c1908a0);
            float m2328f = C2344d0.m2328f(f2, 0.1f, 8.0f);
            if (c1908a0.f3021c != m2328f) {
                c1908a0.f3021c = m2328f;
                c1908a0.f3027i = true;
            }
            C1908a0 c1908a02 = this.f3188c;
            float f3 = c2262n0.f5670c;
            Objects.requireNonNull(c1908a02);
            float m2328f2 = C2344d0.m2328f(f3, 0.1f, 8.0f);
            if (c1908a02.f3022d != m2328f2) {
                c1908a02.f3022d = m2328f2;
                c1908a02.f3027i = true;
            }
            return new C2262n0(m2328f, m2328f2, c2262n0.f5671d);
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.C1928t.b
        /* renamed from: b */
        public long mo1297b(long j2) {
            C1908a0 c1908a0 = this.f3188c;
            long j3 = c1908a0.f3033o;
            if (j3 < IjkMediaMeta.AV_CH_SIDE_RIGHT) {
                return (long) (c1908a0.f3021c * j2);
            }
            int i2 = c1908a0.f3026h.f3078b;
            int i3 = c1908a0.f3025g.f3078b;
            return i2 == i3 ? C2344d0.m2314F(j2, c1908a0.f3032n, j3) : C2344d0.m2314F(j2, c1908a0.f3032n * i2, j3 * i3);
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.C1928t.b
        /* renamed from: c */
        public long mo1298c() {
            return this.f3187b.f3221q;
        }
    }

    /* renamed from: b.l.a.a.a1.t$e */
    public static final class e {

        /* renamed from: a */
        public final C2262n0 f3189a;

        /* renamed from: b */
        public final long f3190b;

        /* renamed from: c */
        public final long f3191c;

        public e(C2262n0 c2262n0, long j2, long j3, a aVar) {
            this.f3189a = c2262n0;
            this.f3190b = j2;
            this.f3191c = j3;
        }
    }

    /* renamed from: b.l.a.a.a1.t$f */
    public final class f implements C1924p.a {
        public f(a aVar) {
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.C1924p.a
        /* renamed from: a */
        public void mo1274a(final int i2, final long j2) {
            if (C1928t.this.f3156j != null) {
                long elapsedRealtime = SystemClock.elapsedRealtime();
                C1928t c1928t = C1928t.this;
                final long j3 = elapsedRealtime - c1928t.f3146P;
                C1931w.b bVar = (C1931w.b) c1928t.f3156j;
                final InterfaceC1921m.a aVar = C1931w.this.f3208w0;
                Handler handler = aVar.f3082a;
                if (handler != null) {
                    handler.post(new Runnable() { // from class: b.l.a.a.a1.b
                        @Override // java.lang.Runnable
                        public final void run() {
                            InterfaceC1921m.a aVar2 = InterfaceC1921m.a.this;
                            int i3 = i2;
                            long j4 = j2;
                            long j5 = j3;
                            InterfaceC1921m interfaceC1921m = aVar2.f3083b;
                            int i4 = C2344d0.f6035a;
                            interfaceC1921m.onAudioSinkUnderrun(i3, j4, j5);
                        }
                    });
                }
                Objects.requireNonNull(C1931w.this);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.C1924p.a
        /* renamed from: b */
        public void mo1275b(long j2) {
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.C1924p.a
        /* renamed from: c */
        public void mo1276c(long j2, long j3, long j4, long j5) {
            C1928t c1928t = C1928t.this;
            if (c1928t.f3158l.f3175a) {
                long j6 = c1928t.f3167u / r2.f3176b;
            }
            c1928t.m1285g();
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.C1924p.a
        /* renamed from: d */
        public void mo1277d(long j2, long j3, long j4, long j5) {
            C1928t c1928t = C1928t.this;
            if (c1928t.f3158l.f3175a) {
                long j6 = c1928t.f3167u / r2.f3176b;
            }
            c1928t.m1285g();
        }
    }

    public C1928t(@Nullable C1918j c1918j, InterfaceC1920l[] interfaceC1920lArr) {
        d dVar = new d(interfaceC1920lArr);
        this.f3147a = c1918j;
        this.f3148b = dVar;
        this.f3153g = new ConditionVariable(true);
        this.f3154h = new C1924p(new f(null));
        C1927s c1927s = new C1927s();
        this.f3149c = c1927s;
        C1910b0 c1910b0 = new C1910b0();
        this.f3150d = c1910b0;
        ArrayList arrayList = new ArrayList();
        Collections.addAll(arrayList, new C1932x(), c1927s, c1910b0);
        Collections.addAll(arrayList, dVar.f3186a);
        this.f3151e = (InterfaceC1920l[]) arrayList.toArray(new InterfaceC1920l[0]);
        this.f3152f = new InterfaceC1920l[]{new C1930v()};
        this.f3132B = 1.0f;
        this.f3172z = 0;
        this.f3160n = C1917i.f3066a;
        this.f3143M = 0;
        this.f3144N = new C1925q(0, 0.0f);
        this.f3162p = C2262n0.f5668a;
        this.f3139I = -1;
        this.f3133C = new InterfaceC1920l[0];
        this.f3134D = new ByteBuffer[0];
        this.f3155i = new ArrayDeque<>();
    }

    /* renamed from: a */
    public final void m1279a(C2262n0 c2262n0, long j2) {
        this.f3155i.add(new e(this.f3158l.f3184j ? this.f3148b.mo1296a(c2262n0) : C2262n0.f5668a, Math.max(0L, j2), this.f3158l.m1299a(m1285g()), null));
        InterfaceC1920l[] interfaceC1920lArr = this.f3158l.f3185k;
        ArrayList arrayList = new ArrayList();
        for (InterfaceC1920l interfaceC1920l : interfaceC1920lArr) {
            if (interfaceC1920l.mo1253b()) {
                arrayList.add(interfaceC1920l);
            } else {
                interfaceC1920l.flush();
            }
        }
        int size = arrayList.size();
        this.f3133C = (InterfaceC1920l[]) arrayList.toArray(new InterfaceC1920l[size]);
        this.f3134D = new ByteBuffer[size];
        m1283e();
    }

    /* JADX WARN: Removed duplicated region for block: B:47:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00d7  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x010c  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00d3 A[FALL_THROUGH] */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m1280b(int r20, int r21, int r22, int r23, @androidx.annotation.Nullable int[] r24, int r25, int r26) {
        /*
            Method dump skipped, instructions count: 300
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1928t.m1280b(int, int, int, int, int[], int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0023  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x003a  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:17:0x0034 -> B:7:0x0014). Please report as a decompilation issue!!! */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m1281c() {
        /*
            r9 = this;
            int r0 = r9.f3139I
            r1 = -1
            r2 = 1
            r3 = 0
            if (r0 != r1) goto L16
            b.l.a.a.a1.t$c r0 = r9.f3158l
            boolean r0 = r0.f3183i
            if (r0 == 0) goto Lf
            r0 = 0
            goto L12
        Lf:
            b.l.a.a.a1.l[] r0 = r9.f3133C
            int r0 = r0.length
        L12:
            r9.f3139I = r0
        L14:
            r0 = 1
            goto L17
        L16:
            r0 = 0
        L17:
            int r4 = r9.f3139I
            b.l.a.a.a1.l[] r5 = r9.f3133C
            int r6 = r5.length
            r7 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            if (r4 >= r6) goto L3a
            r4 = r5[r4]
            if (r0 == 0) goto L2a
            r4.mo1258g()
        L2a:
            r9.m1291m(r7)
            boolean r0 = r4.mo1254c()
            if (r0 != 0) goto L34
            return r3
        L34:
            int r0 = r9.f3139I
            int r0 = r0 + r2
            r9.f3139I = r0
            goto L14
        L3a:
            java.nio.ByteBuffer r0 = r9.f3136F
            if (r0 == 0) goto L46
            r9.m1295q(r0, r7)
            java.nio.ByteBuffer r0 = r9.f3136F
            if (r0 == 0) goto L46
            return r3
        L46:
            r9.f3139I = r1
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1928t.m1281c():boolean");
    }

    /* renamed from: d */
    public void m1282d() {
        if (m1288j()) {
            this.f3167u = 0L;
            this.f3168v = 0L;
            this.f3169w = 0L;
            this.f3170x = 0L;
            this.f3171y = 0;
            C2262n0 c2262n0 = this.f3161o;
            if (c2262n0 != null) {
                this.f3162p = c2262n0;
                this.f3161o = null;
            } else if (!this.f3155i.isEmpty()) {
                this.f3162p = this.f3155i.getLast().f3189a;
            }
            this.f3155i.clear();
            this.f3163q = 0L;
            this.f3164r = 0L;
            this.f3150d.f3045o = 0L;
            m1283e();
            this.f3135E = null;
            this.f3136F = null;
            this.f3141K = false;
            this.f3140J = false;
            this.f3139I = -1;
            this.f3165s = null;
            this.f3166t = 0;
            this.f3172z = 0;
            AudioTrack audioTrack = this.f3154h.f3097c;
            Objects.requireNonNull(audioTrack);
            if (audioTrack.getPlayState() == 3) {
                this.f3159m.pause();
            }
            AudioTrack audioTrack2 = this.f3159m;
            this.f3159m = null;
            c cVar = this.f3157k;
            if (cVar != null) {
                this.f3158l = cVar;
                this.f3157k = null;
            }
            C1924p c1924p = this.f3154h;
            c1924p.f3104j = 0L;
            c1924p.f3115u = 0;
            c1924p.f3114t = 0;
            c1924p.f3105k = 0L;
            c1924p.f3097c = null;
            c1924p.f3100f = null;
            this.f3153g.close();
            new a(audioTrack2).start();
        }
    }

    /* renamed from: e */
    public final void m1283e() {
        int i2 = 0;
        while (true) {
            InterfaceC1920l[] interfaceC1920lArr = this.f3133C;
            if (i2 >= interfaceC1920lArr.length) {
                return;
            }
            InterfaceC1920l interfaceC1920l = interfaceC1920lArr[i2];
            interfaceC1920l.flush();
            this.f3134D[i2] = interfaceC1920l.mo1255d();
            i2++;
        }
    }

    /* renamed from: f */
    public C2262n0 m1284f() {
        C2262n0 c2262n0 = this.f3161o;
        return c2262n0 != null ? c2262n0 : !this.f3155i.isEmpty() ? this.f3155i.getLast().f3189a : this.f3162p;
    }

    /* renamed from: g */
    public final long m1285g() {
        return this.f3158l.f3175a ? this.f3169w / r0.f3178d : this.f3170x;
    }

    /* JADX WARN: Code restructure failed: missing block: B:210:0x01e5, code lost:
    
        if (r4.m1272b() == 0) goto L81;
     */
    /* JADX WARN: Removed duplicated region for block: B:113:0x0382 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x01b2 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0209 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:82:0x020b  */
    /* renamed from: h */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean m1286h(java.nio.ByteBuffer r24, long r25) {
        /*
            Method dump skipped, instructions count: 1132
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1928t.m1286h(java.nio.ByteBuffer, long):boolean");
    }

    /* renamed from: i */
    public boolean m1287i() {
        return m1288j() && this.f3154h.m1273c(m1285g());
    }

    /* renamed from: j */
    public final boolean m1288j() {
        return this.f3159m != null;
    }

    /* renamed from: k */
    public void m1289k() {
        this.f3142L = true;
        if (m1288j()) {
            C1923o c1923o = this.f3154h.f3100f;
            Objects.requireNonNull(c1923o);
            c1923o.m1269a();
            this.f3159m.play();
        }
    }

    /* renamed from: l */
    public final void m1290l() {
        if (this.f3141K) {
            return;
        }
        this.f3141K = true;
        C1924p c1924p = this.f3154h;
        long m1285g = m1285g();
        c1924p.f3118x = c1924p.m1272b();
        c1924p.f3116v = SystemClock.elapsedRealtime() * 1000;
        c1924p.f3119y = m1285g;
        this.f3159m.stop();
        this.f3166t = 0;
    }

    /* renamed from: m */
    public final void m1291m(long j2) {
        ByteBuffer byteBuffer;
        int length = this.f3133C.length;
        int i2 = length;
        while (i2 >= 0) {
            if (i2 > 0) {
                byteBuffer = this.f3134D[i2 - 1];
            } else {
                byteBuffer = this.f3135E;
                if (byteBuffer == null) {
                    byteBuffer = InterfaceC1920l.f3076a;
                }
            }
            if (i2 == length) {
                m1295q(byteBuffer, j2);
            } else {
                InterfaceC1920l interfaceC1920l = this.f3133C[i2];
                interfaceC1920l.mo1256e(byteBuffer);
                ByteBuffer mo1255d = interfaceC1920l.mo1255d();
                this.f3134D[i2] = mo1255d;
                if (mo1255d.hasRemaining()) {
                    i2++;
                }
            }
            if (byteBuffer.hasRemaining()) {
                return;
            } else {
                i2--;
            }
        }
    }

    /* renamed from: n */
    public void m1292n() {
        m1282d();
        for (InterfaceC1920l interfaceC1920l : this.f3151e) {
            interfaceC1920l.reset();
        }
        for (InterfaceC1920l interfaceC1920l2 : this.f3152f) {
            interfaceC1920l2.reset();
        }
        this.f3143M = 0;
        this.f3142L = false;
    }

    /* renamed from: o */
    public final void m1293o() {
        if (m1288j()) {
            if (C2344d0.f6035a >= 21) {
                this.f3159m.setVolume(this.f3132B);
                return;
            }
            AudioTrack audioTrack = this.f3159m;
            float f2 = this.f3132B;
            audioTrack.setStereoVolume(f2, f2);
        }
    }

    /* renamed from: p */
    public boolean m1294p(int i2, int i3) {
        if (C2344d0.m2346x(i3)) {
            return i3 != 4 || C2344d0.f6035a >= 21;
        }
        C1918j c1918j = this.f3147a;
        if (c1918j != null) {
            if ((Arrays.binarySearch(c1918j.f3074c, i3) >= 0) && (i2 == -1 || i2 <= this.f3147a.f3075d)) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:49:0x00e2, code lost:
    
        if (r15 < r14) goto L54;
     */
    /* renamed from: q */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1295q(java.nio.ByteBuffer r13, long r14) {
        /*
            Method dump skipped, instructions count: 293
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1928t.m1295q(java.nio.ByteBuffer, long):void");
    }
}
