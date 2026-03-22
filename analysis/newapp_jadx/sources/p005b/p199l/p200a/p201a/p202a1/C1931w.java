package p005b.p199l.p200a.p201a.p202a1;

import android.app.UiModeManager;
import android.content.Context;
import android.media.AudioTrack;
import android.media.MediaCodec;
import android.media.MediaFormat;
import android.os.Handler;
import androidx.annotation.CallSuper;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.p202a1.C1928t;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1922n;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p205d1.C1957h;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p219g1.AbstractC2073f;
import p005b.p199l.p200a.p201a.p219g1.C2070c;
import p005b.p199l.p200a.p201a.p219g1.C2072e;
import p005b.p199l.p200a.p201a.p219g1.C2075h;
import p005b.p199l.p200a.p201a.p219g1.InterfaceC2074g;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import tv.danmaku.ijk.media.player.misc.IMediaFormat;

/* renamed from: b.l.a.a.a1.w */
/* loaded from: classes.dex */
public class C1931w extends AbstractC2073f implements InterfaceC2356p {

    /* renamed from: A0 */
    public boolean f3197A0;

    /* renamed from: B0 */
    public boolean f3198B0;

    /* renamed from: C0 */
    public boolean f3199C0;

    /* renamed from: D0 */
    public MediaFormat f3200D0;

    /* renamed from: E0 */
    @Nullable
    public Format f3201E0;

    /* renamed from: F0 */
    public long f3202F0;

    /* renamed from: G0 */
    public boolean f3203G0;

    /* renamed from: H0 */
    public boolean f3204H0;

    /* renamed from: I0 */
    public long f3205I0;

    /* renamed from: J0 */
    public int f3206J0;

    /* renamed from: v0 */
    public final Context f3207v0;

    /* renamed from: w0 */
    public final InterfaceC1921m.a f3208w0;

    /* renamed from: x0 */
    public final InterfaceC1922n f3209x0;

    /* renamed from: y0 */
    public final long[] f3210y0;

    /* renamed from: z0 */
    public int f3211z0;

    /* renamed from: b.l.a.a.a1.w$b */
    public final class b implements InterfaceC1922n.c {
        public b(a aVar) {
        }
    }

    @Deprecated
    public C1931w(Context context, InterfaceC2074g interfaceC2074g, @Nullable InterfaceC1954e<C1957h> interfaceC1954e, boolean z, boolean z2, @Nullable Handler handler, @Nullable InterfaceC1921m interfaceC1921m, InterfaceC1922n interfaceC1922n) {
        super(1, interfaceC2074g, interfaceC1954e, z, z2, 44100.0f);
        this.f3207v0 = context.getApplicationContext();
        this.f3209x0 = interfaceC1922n;
        this.f3205I0 = -9223372036854775807L;
        this.f3210y0 = new long[10];
        this.f3208w0 = new InterfaceC1921m.a(handler, interfaceC1921m);
        ((C1928t) interfaceC1922n).f3156j = new b(null);
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: A */
    public void mo1301A() {
        ((C1928t) this.f3209x0).m1289k();
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: B */
    public void mo1302B() {
        m1323r0();
        C1928t c1928t = (C1928t) this.f3209x0;
        boolean z = false;
        c1928t.f3142L = false;
        if (c1928t.m1288j()) {
            C1924p c1924p = c1928t.f3154h;
            c1924p.f3104j = 0L;
            c1924p.f3115u = 0;
            c1924p.f3114t = 0;
            c1924p.f3105k = 0L;
            if (c1924p.f3116v == -9223372036854775807L) {
                C1923o c1923o = c1924p.f3100f;
                Objects.requireNonNull(c1923o);
                c1923o.m1269a();
                z = true;
            }
            if (z) {
                c1928t.f3159m.pause();
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: C */
    public void mo1303C(Format[] formatArr, long j2) {
        long j3 = this.f3205I0;
        if (j3 != -9223372036854775807L) {
            int i2 = this.f3206J0;
            long[] jArr = this.f3210y0;
            if (i2 == jArr.length) {
                long j4 = jArr[i2 - 1];
            } else {
                this.f3206J0 = i2 + 1;
            }
            jArr[this.f3206J0 - 1] = j3;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: H */
    public int mo1304H(MediaCodec mediaCodec, C2072e c2072e, Format format, Format format2) {
        if (m1320p0(c2072e, format2) <= this.f3211z0 && format.f9231B == 0 && format.f9232C == 0 && format2.f9231B == 0 && format2.f9232C == 0) {
            if (c2072e.m1659f(format, format2, true)) {
                return 3;
            }
            if (C2344d0.m2323a(format.f9245l, format2.f9245l) && format.f9258y == format2.f9258y && format.f9259z == format2.f9259z && format.f9230A == format2.f9230A && format.m4041N(format2) && !"audio/opus".equals(format.f9245l)) {
                return 1;
            }
        }
        return 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0102  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x010b  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0122  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x012a  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00b4  */
    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: I */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1305I(p005b.p199l.p200a.p201a.p219g1.C2072e r9, android.media.MediaCodec r10, com.google.android.exoplayer2.Format r11, @androidx.annotation.Nullable android.media.MediaCrypto r12, float r13) {
        /*
            Method dump skipped, instructions count: 301
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1931w.mo1305I(b.l.a.a.g1.e, android.media.MediaCodec, com.google.android.exoplayer2.Format, android.media.MediaCrypto, float):void");
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: R */
    public float mo1306R(float f2, Format format, Format[] formatArr) {
        int i2 = -1;
        for (Format format2 : formatArr) {
            int i3 = format2.f9259z;
            if (i3 != -1) {
                i2 = Math.max(i2, i3);
            }
        }
        if (i2 == -1) {
            return -1.0f;
        }
        return f2 * i2;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: S */
    public List<C2072e> mo1307S(InterfaceC2074g interfaceC2074g, Format format, boolean z) {
        C2072e mo1687a;
        String str = format.f9245l;
        if (str == null) {
            return Collections.emptyList();
        }
        if ((m1321q0(format.f9258y, str) != 0) && (mo1687a = interfaceC2074g.mo1687a()) != null) {
            return Collections.singletonList(mo1687a);
        }
        List<C2072e> mo1688b = interfaceC2074g.mo1688b(str, z, false);
        Pattern pattern = C2075h.f4352a;
        ArrayList arrayList = new ArrayList(mo1688b);
        C2075h.m1697i(arrayList, new C2070c(format));
        if ("audio/eac3-joc".equals(str)) {
            ArrayList arrayList2 = new ArrayList(arrayList);
            arrayList2.addAll(interfaceC2074g.mo1688b("audio/eac3", z, false));
            arrayList = arrayList2;
        }
        return Collections.unmodifiableList(arrayList);
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: X */
    public void mo1308X(final String str, final long j2, final long j3) {
        final InterfaceC1921m.a aVar = this.f3208w0;
        Handler handler = aVar.f3082a;
        if (handler != null) {
            handler.post(new Runnable() { // from class: b.l.a.a.a1.d
                @Override // java.lang.Runnable
                public final void run() {
                    InterfaceC1921m.a aVar2 = InterfaceC1921m.a.this;
                    String str2 = str;
                    long j4 = j2;
                    long j5 = j3;
                    InterfaceC1921m interfaceC1921m = aVar2.f3083b;
                    int i2 = C2344d0.f6035a;
                    interfaceC1921m.onAudioDecoderInitialized(str2, j4, j5);
                }
            });
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: Y */
    public void mo1309Y(C1964f0 c1964f0) {
        super.mo1309Y(c1964f0);
        final Format format = c1964f0.f3394c;
        this.f3201E0 = format;
        final InterfaceC1921m.a aVar = this.f3208w0;
        Handler handler = aVar.f3082a;
        if (handler != null) {
            handler.post(new Runnable() { // from class: b.l.a.a.a1.a
                @Override // java.lang.Runnable
                public final void run() {
                    InterfaceC1921m.a aVar2 = InterfaceC1921m.a.this;
                    Format format2 = format;
                    InterfaceC1921m interfaceC1921m = aVar2.f3083b;
                    int i2 = C2344d0.f6035a;
                    interfaceC1921m.onAudioInputFormatChanged(format2);
                }
            });
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: Z */
    public void mo1310Z(MediaCodec mediaCodec, MediaFormat mediaFormat) {
        int i2;
        int i3;
        int[] iArr;
        int i4;
        MediaFormat mediaFormat2 = this.f3200D0;
        if (mediaFormat2 != null) {
            i3 = m1321q0(mediaFormat2.getInteger("channel-count"), mediaFormat2.getString(IMediaFormat.KEY_MIME));
            mediaFormat = mediaFormat2;
        } else {
            if (mediaFormat.containsKey("v-bits-per-sample")) {
                i2 = C2344d0.m2336n(mediaFormat.getInteger("v-bits-per-sample"));
            } else {
                Format format = this.f3201E0;
                i2 = "audio/raw".equals(format.f9245l) ? format.f9230A : 2;
            }
            i3 = i2;
        }
        int integer = mediaFormat.getInteger("channel-count");
        int integer2 = mediaFormat.getInteger("sample-rate");
        if (this.f3198B0 && integer == 6 && (i4 = this.f3201E0.f9258y) < 6) {
            iArr = new int[i4];
            for (int i5 = 0; i5 < this.f3201E0.f9258y; i5++) {
                iArr[i5] = i5;
            }
        } else {
            iArr = null;
        }
        int[] iArr2 = iArr;
        try {
            InterfaceC1922n interfaceC1922n = this.f3209x0;
            Format format2 = this.f3201E0;
            ((C1928t) interfaceC1922n).m1280b(i3, integer, integer2, 0, iArr2, format2.f9231B, format2.f9232C);
        } catch (InterfaceC1922n.a e2) {
            throw m2666u(e2, this.f3201E0);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    @CallSuper
    /* renamed from: a0 */
    public void mo1311a0(long j2) {
        while (true) {
            int i2 = this.f3206J0;
            if (i2 == 0) {
                return;
            }
            long[] jArr = this.f3210y0;
            if (j2 < jArr[0]) {
                return;
            }
            C1928t c1928t = (C1928t) this.f3209x0;
            if (c1928t.f3172z == 1) {
                c1928t.f3172z = 2;
            }
            int i3 = i2 - 1;
            this.f3206J0 = i3;
            System.arraycopy(jArr, 1, jArr, 0, i3);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: b */
    public C2262n0 mo1312b() {
        return ((C1928t) this.f3209x0).m1284f();
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: b0 */
    public void mo1313b0(C1945e c1945e) {
        if (this.f3203G0 && !c1945e.isDecodeOnly()) {
            if (Math.abs(c1945e.f3307f - this.f3202F0) > 500000) {
                this.f3202F0 = c1945e.f3307f;
            }
            this.f3203G0 = false;
        }
        this.f3205I0 = Math.max(c1945e.f3307f, this.f3205I0);
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: c */
    public boolean mo1314c() {
        if (this.f4331p0) {
            C1928t c1928t = (C1928t) this.f3209x0;
            if (!c1928t.m1288j() || (c1928t.f3140J && !c1928t.m1287i())) {
                return true;
            }
        }
        return false;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: d0 */
    public boolean mo1315d0(long j2, long j3, MediaCodec mediaCodec, ByteBuffer byteBuffer, int i2, int i3, long j4, boolean z, boolean z2, Format format) {
        if (this.f3199C0 && j4 == 0 && (i3 & 4) != 0) {
            long j5 = this.f3205I0;
            if (j5 != -9223372036854775807L) {
                j4 = j5;
            }
        }
        if (this.f3197A0 && (i3 & 2) != 0) {
            mediaCodec.releaseOutputBuffer(i2, false);
            return true;
        }
        if (z) {
            mediaCodec.releaseOutputBuffer(i2, false);
            this.f4341u0.f3301f++;
            C1928t c1928t = (C1928t) this.f3209x0;
            if (c1928t.f3172z == 1) {
                c1928t.f3172z = 2;
            }
            return true;
        }
        try {
            if (!((C1928t) this.f3209x0).m1286h(byteBuffer, j4)) {
                return false;
            }
            mediaCodec.releaseOutputBuffer(i2, false);
            this.f4341u0.f3300e++;
            return true;
        } catch (InterfaceC1922n.b | InterfaceC1922n.d e2) {
            throw m2666u(e2, this.f3201E0);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: g0 */
    public void mo1316g0() {
        try {
            C1928t c1928t = (C1928t) this.f3209x0;
            if (!c1928t.f3140J && c1928t.m1288j() && c1928t.m1281c()) {
                c1928t.m1290l();
                c1928t.f3140J = true;
            }
        } catch (InterfaceC1922n.d e2) {
            throw m2666u(e2, this.f3201E0);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: i */
    public long mo1317i() {
        if (this.f6318h == 2) {
            m1323r0();
        }
        return this.f3202F0;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.InterfaceC2396t0
    public boolean isReady() {
        return ((C1928t) this.f3209x0).m1287i() || super.isReady();
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u, p005b.p199l.p200a.p201a.C2392r0.b
    /* renamed from: k */
    public void mo1318k(int i2, @Nullable Object obj) {
        if (i2 == 2) {
            InterfaceC1922n interfaceC1922n = this.f3209x0;
            float floatValue = ((Float) obj).floatValue();
            C1928t c1928t = (C1928t) interfaceC1922n;
            if (c1928t.f3132B != floatValue) {
                c1928t.f3132B = floatValue;
                c1928t.m1293o();
                return;
            }
            return;
        }
        if (i2 == 3) {
            C1917i c1917i = (C1917i) obj;
            C1928t c1928t2 = (C1928t) this.f3209x0;
            if (c1928t2.f3160n.equals(c1917i)) {
                return;
            }
            c1928t2.f3160n = c1917i;
            if (c1928t2.f3145O) {
                return;
            }
            c1928t2.m1282d();
            c1928t2.f3143M = 0;
            return;
        }
        if (i2 != 5) {
            return;
        }
        C1925q c1925q = (C1925q) obj;
        C1928t c1928t3 = (C1928t) this.f3209x0;
        if (c1928t3.f3144N.equals(c1925q)) {
            return;
        }
        int i3 = c1925q.f3120a;
        float f2 = c1925q.f3121b;
        AudioTrack audioTrack = c1928t3.f3159m;
        if (audioTrack != null) {
            if (c1928t3.f3144N.f3120a != i3) {
                audioTrack.attachAuxEffect(i3);
            }
            if (i3 != 0) {
                c1928t3.f3159m.setAuxEffectSendLevel(f2);
            }
        }
        c1928t3.f3144N = c1925q;
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x005f, code lost:
    
        if (((p005b.p199l.p200a.p201a.p202a1.C1928t) r6.f3209x0).m1294p(r9.f9258y, r9.f9230A) != false) goto L34;
     */
    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: m0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int mo1319m0(p005b.p199l.p200a.p201a.p219g1.InterfaceC2074g r7, @androidx.annotation.Nullable p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e<p005b.p199l.p200a.p201a.p205d1.C1957h> r8, com.google.android.exoplayer2.Format r9) {
        /*
            r6 = this;
            java.lang.String r0 = r9.f9245l
            boolean r1 = p005b.p199l.p200a.p201a.p250p1.C2357q.m2545h(r0)
            r2 = 0
            if (r1 != 0) goto La
            return r2
        La:
            int r1 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            r3 = 21
            if (r1 < r3) goto L13
            r1 = 32
            goto L14
        L13:
            r1 = 0
        L14:
            com.google.android.exoplayer2.drm.DrmInitData r3 = r9.f9248o
            r4 = 1
            if (r3 == 0) goto L32
            java.lang.Class<b.l.a.a.d1.h> r3 = p005b.p199l.p200a.p201a.p205d1.C1957h.class
            java.lang.Class<? extends b.l.a.a.d1.g> r5 = r9.f9235F
            boolean r3 = r3.equals(r5)
            if (r3 != 0) goto L32
            java.lang.Class<? extends b.l.a.a.d1.g> r3 = r9.f9235F
            if (r3 != 0) goto L30
            com.google.android.exoplayer2.drm.DrmInitData r3 = r9.f9248o
            boolean r8 = p005b.p199l.p200a.p201a.AbstractC2397u.m2664F(r8, r3)
            if (r8 == 0) goto L30
            goto L32
        L30:
            r8 = 0
            goto L33
        L32:
            r8 = 1
        L33:
            if (r8 == 0) goto L4b
            int r3 = r9.f9258y
            int r3 = r6.m1321q0(r3, r0)
            if (r3 == 0) goto L3f
            r3 = 1
            goto L40
        L3f:
            r3 = 0
        L40:
            if (r3 == 0) goto L4b
            b.l.a.a.g1.e r3 = r7.mo1687a()
            if (r3 == 0) goto L4b
            r7 = r1 | 12
            return r7
        L4b:
            java.lang.String r3 = "audio/raw"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L61
            b.l.a.a.a1.n r0 = r6.f3209x0
            int r3 = r9.f9258y
            int r5 = r9.f9230A
            b.l.a.a.a1.t r0 = (p005b.p199l.p200a.p201a.p202a1.C1928t) r0
            boolean r0 = r0.m1294p(r3, r5)
            if (r0 == 0) goto L6e
        L61:
            b.l.a.a.a1.n r0 = r6.f3209x0
            int r3 = r9.f9258y
            b.l.a.a.a1.t r0 = (p005b.p199l.p200a.p201a.p202a1.C1928t) r0
            r5 = 2
            boolean r0 = r0.m1294p(r3, r5)
            if (r0 != 0) goto L6f
        L6e:
            return r4
        L6f:
            java.util.List r7 = r6.mo1307S(r7, r9, r2)
            boolean r0 = r7.isEmpty()
            if (r0 == 0) goto L7a
            return r4
        L7a:
            if (r8 != 0) goto L7d
            return r5
        L7d:
            java.lang.Object r7 = r7.get(r2)
            b.l.a.a.g1.e r7 = (p005b.p199l.p200a.p201a.p219g1.C2072e) r7
            boolean r8 = r7.m1657d(r9)
            if (r8 == 0) goto L92
            boolean r7 = r7.m1658e(r9)
            if (r7 == 0) goto L92
            r7 = 16
            goto L94
        L92:
            r7 = 8
        L94:
            if (r8 == 0) goto L98
            r8 = 4
            goto L99
        L98:
            r8 = 3
        L99:
            r7 = r7 | r8
            r7 = r7 | r1
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1931w.mo1319m0(b.l.a.a.g1.g, b.l.a.a.d1.e, com.google.android.exoplayer2.Format):int");
    }

    /* renamed from: p0 */
    public final int m1320p0(C2072e c2072e, Format format) {
        int i2;
        if ("OMX.google.raw.decoder".equals(c2072e.f4280a) && (i2 = C2344d0.f6035a) < 24) {
            if (i2 != 23) {
                return -1;
            }
            UiModeManager uiModeManager = (UiModeManager) this.f3207v0.getApplicationContext().getSystemService("uimode");
            if (!(uiModeManager != null && uiModeManager.getCurrentModeType() == 4)) {
                return -1;
            }
        }
        return format.f9246m;
    }

    /* renamed from: q0 */
    public int m1321q0(int i2, String str) {
        if ("audio/eac3-joc".equals(str)) {
            if (((C1928t) this.f3209x0).m1294p(-1, 18)) {
                return C2357q.m2539b("audio/eac3-joc");
            }
            str = "audio/eac3";
        }
        int m2539b = C2357q.m2539b(str);
        if (((C1928t) this.f3209x0).m1294p(i2, m2539b)) {
            return m2539b;
        }
        return 0;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u, p005b.p199l.p200a.p201a.InterfaceC2396t0
    @Nullable
    /* renamed from: r */
    public InterfaceC2356p mo1322r() {
        return this;
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0274  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x027b  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0212  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0125  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01b9 A[Catch: Exception -> 0x01c6, TRY_LEAVE, TryCatch #0 {Exception -> 0x01c6, blocks: (B:67:0x0191, B:69:0x01b9), top: B:66:0x0191 }] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01de A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:78:0x01e6  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0241  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x025b  */
    /* renamed from: r0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1323r0() {
        /*
            Method dump skipped, instructions count: 721
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1931w.m1323r0():void");
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: s */
    public void mo1324s(C2262n0 c2262n0) {
        C1928t c1928t = (C1928t) this.f3209x0;
        C1928t.c cVar = c1928t.f3158l;
        if (cVar != null && !cVar.f3184j) {
            c1928t.f3162p = C2262n0.f5668a;
        } else {
            if (c2262n0.equals(c1928t.m1284f())) {
                return;
            }
            if (c1928t.m1288j()) {
                c1928t.f3161o = c2262n0;
            } else {
                c1928t.f3162p = c2262n0;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: w */
    public void mo1325w() {
        try {
            this.f3205I0 = -9223372036854775807L;
            this.f3206J0 = 0;
            ((C1928t) this.f3209x0).m1282d();
            try {
                super.mo1325w();
            } finally {
            }
        } catch (Throwable th) {
            try {
                super.mo1325w();
                throw th;
            } finally {
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: x */
    public void mo1326x(boolean z) {
        super.mo1326x(z);
        final InterfaceC1921m.a aVar = this.f3208w0;
        final C1944d c1944d = this.f4341u0;
        Handler handler = aVar.f3082a;
        if (handler != null) {
            handler.post(new Runnable() { // from class: b.l.a.a.a1.e
                @Override // java.lang.Runnable
                public final void run() {
                    InterfaceC1921m.a aVar2 = InterfaceC1921m.a.this;
                    C1944d c1944d2 = c1944d;
                    InterfaceC1921m interfaceC1921m = aVar2.f3083b;
                    int i2 = C2344d0.f6035a;
                    interfaceC1921m.onAudioEnabled(c1944d2);
                }
            });
        }
        int i2 = this.f6316f.f6326b;
        if (i2 == 0) {
            C1928t c1928t = (C1928t) this.f3209x0;
            if (c1928t.f3145O) {
                c1928t.f3145O = false;
                c1928t.f3143M = 0;
                c1928t.m1282d();
                return;
            }
            return;
        }
        C1928t c1928t2 = (C1928t) this.f3209x0;
        Objects.requireNonNull(c1928t2);
        C4195m.m4771I(C2344d0.f6035a >= 21);
        if (c1928t2.f3145O && c1928t2.f3143M == i2) {
            return;
        }
        c1928t2.f3145O = true;
        c1928t2.f3143M = i2;
        c1928t2.m1282d();
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: y */
    public void mo1327y(long j2, boolean z) {
        this.f4329o0 = false;
        this.f4331p0 = false;
        this.f4339t0 = false;
        m1667N();
        this.f4343w.m2301b();
        ((C1928t) this.f3209x0).m1282d();
        this.f3202F0 = j2;
        this.f3203G0 = true;
        this.f3204H0 = true;
        this.f3205I0 = -9223372036854775807L;
        this.f3206J0 = 0;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: z */
    public void mo1328z() {
        try {
            super.mo1328z();
        } finally {
            ((C1928t) this.f3209x0).m1292n();
        }
    }
}
