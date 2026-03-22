package p005b.p199l.p200a.p201a.p251q1;

import android.annotation.TargetApi;
import android.content.Context;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaFormat;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.util.Pair;
import android.view.Surface;
import androidx.annotation.CallSuper;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.video.DummySurface;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import p005b.p199l.p200a.p201a.AbstractC2397u;
import p005b.p199l.p200a.p201a.C1964f0;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import p005b.p199l.p200a.p201a.p251q1.C2383o;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r;

/* renamed from: b.l.a.a.q1.k */
/* loaded from: classes.dex */
public class C2379k extends AbstractC2073f {

    /* renamed from: v0 */
    public static final int[] f6186v0 = {1920, 1600, 1440, 1280, 960, 854, 640, 540, 480};

    /* renamed from: w0 */
    public static boolean f6187w0;

    /* renamed from: x0 */
    public static boolean f6188x0;

    /* renamed from: A0 */
    public final InterfaceC2386r.a f6189A0;

    /* renamed from: B0 */
    public final long f6190B0;

    /* renamed from: C0 */
    public final int f6191C0;

    /* renamed from: D0 */
    public final boolean f6192D0;

    /* renamed from: E0 */
    public final long[] f6193E0;

    /* renamed from: F0 */
    public final long[] f6194F0;

    /* renamed from: G0 */
    public a f6195G0;

    /* renamed from: H0 */
    public boolean f6196H0;

    /* renamed from: I0 */
    public boolean f6197I0;

    /* renamed from: J0 */
    public Surface f6198J0;

    /* renamed from: K0 */
    public Surface f6199K0;

    /* renamed from: L0 */
    public int f6200L0;

    /* renamed from: M0 */
    public boolean f6201M0;

    /* renamed from: N0 */
    public long f6202N0;

    /* renamed from: O0 */
    public long f6203O0;

    /* renamed from: P0 */
    public long f6204P0;

    /* renamed from: Q0 */
    public int f6205Q0;

    /* renamed from: R0 */
    public int f6206R0;

    /* renamed from: S0 */
    public int f6207S0;

    /* renamed from: T0 */
    public long f6208T0;

    /* renamed from: U0 */
    public int f6209U0;

    /* renamed from: V0 */
    public float f6210V0;

    /* renamed from: W0 */
    @Nullable
    public MediaFormat f6211W0;

    /* renamed from: X0 */
    public int f6212X0;

    /* renamed from: Y0 */
    public int f6213Y0;

    /* renamed from: Z0 */
    public int f6214Z0;

    /* renamed from: a1 */
    public float f6215a1;

    /* renamed from: b1 */
    public int f6216b1;

    /* renamed from: c1 */
    public int f6217c1;

    /* renamed from: d1 */
    public int f6218d1;

    /* renamed from: e1 */
    public float f6219e1;

    /* renamed from: f1 */
    public boolean f6220f1;

    /* renamed from: g1 */
    public int f6221g1;

    /* renamed from: h1 */
    @Nullable
    public b f6222h1;

    /* renamed from: i1 */
    public long f6223i1;

    /* renamed from: j1 */
    public long f6224j1;

    /* renamed from: k1 */
    public int f6225k1;

    /* renamed from: l1 */
    @Nullable
    public InterfaceC2382n f6226l1;

    /* renamed from: y0 */
    public final Context f6227y0;

    /* renamed from: z0 */
    public final C2383o f6228z0;

    /* renamed from: b.l.a.a.q1.k$a */
    public static final class a {

        /* renamed from: a */
        public final int f6229a;

        /* renamed from: b */
        public final int f6230b;

        /* renamed from: c */
        public final int f6231c;

        public a(int i2, int i3, int i4) {
            this.f6229a = i2;
            this.f6230b = i3;
            this.f6231c = i4;
        }
    }

    @TargetApi(23)
    /* renamed from: b.l.a.a.q1.k$b */
    public final class b implements MediaCodec.OnFrameRenderedListener, Handler.Callback {

        /* renamed from: c */
        public final Handler f6232c;

        public b(MediaCodec mediaCodec) {
            Handler handler = new Handler(this);
            this.f6232c = handler;
            mediaCodec.setOnFrameRenderedListener(this, handler);
        }

        /* renamed from: a */
        public final void m2636a(long j2) {
            C2379k c2379k = C2379k.this;
            if (this != c2379k.f6222h1) {
                return;
            }
            if (j2 == Long.MAX_VALUE) {
                c2379k.f4339t0 = true;
            } else {
                c2379k.m2621B0(j2);
            }
        }

        @Override // android.os.Handler.Callback
        public boolean handleMessage(Message message) {
            if (message.what != 0) {
                return false;
            }
            m2636a((C2344d0.m2321M(message.arg1) << 32) | C2344d0.m2321M(message.arg2));
            return true;
        }

        @Override // android.media.MediaCodec.OnFrameRenderedListener
        public void onFrameRendered(MediaCodec mediaCodec, long j2, long j3) {
            if (C2344d0.f6035a >= 30) {
                m2636a(j2);
            } else {
                this.f6232c.sendMessageAtFrontOfQueue(Message.obtain(this.f6232c, 0, (int) (j2 >> 32), (int) j2));
            }
        }
    }

    @Deprecated
    public C2379k(Context context, InterfaceC2074g interfaceC2074g, long j2, @Nullable InterfaceC1954e<C1957h> interfaceC1954e, boolean z, boolean z2, @Nullable Handler handler, @Nullable InterfaceC2386r interfaceC2386r, int i2) {
        super(2, interfaceC2074g, interfaceC1954e, z, z2, 30.0f);
        this.f6190B0 = j2;
        this.f6191C0 = i2;
        Context applicationContext = context.getApplicationContext();
        this.f6227y0 = applicationContext;
        this.f6228z0 = new C2383o(applicationContext);
        this.f6189A0 = new InterfaceC2386r.a(handler, interfaceC2386r);
        this.f6192D0 = "NVIDIA".equals(C2344d0.f6037c);
        this.f6193E0 = new long[10];
        this.f6194F0 = new long[10];
        this.f6224j1 = -9223372036854775807L;
        this.f6223i1 = -9223372036854775807L;
        this.f6203O0 = -9223372036854775807L;
        this.f6212X0 = -1;
        this.f6213Y0 = -1;
        this.f6215a1 = -1.0f;
        this.f6210V0 = -1.0f;
        this.f6200L0 = 1;
        m2630q0();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* renamed from: s0 */
    public static int m2616s0(C2072e c2072e, String str, int i2, int i3) {
        char c2;
        int i4;
        if (i2 == -1 || i3 == -1) {
            return -1;
        }
        str.hashCode();
        int i5 = 4;
        switch (str.hashCode()) {
            case -1664118616:
                if (str.equals("video/3gpp")) {
                    c2 = 0;
                    break;
                }
                c2 = 65535;
                break;
            case -1662541442:
                if (str.equals("video/hevc")) {
                    c2 = 1;
                    break;
                }
                c2 = 65535;
                break;
            case 1187890754:
                if (str.equals("video/mp4v-es")) {
                    c2 = 2;
                    break;
                }
                c2 = 65535;
                break;
            case 1331836730:
                if (str.equals("video/avc")) {
                    c2 = 3;
                    break;
                }
                c2 = 65535;
                break;
            case 1599127256:
                if (str.equals("video/x-vnd.on2.vp8")) {
                    c2 = 4;
                    break;
                }
                c2 = 65535;
                break;
            case 1599127257:
                if (str.equals("video/x-vnd.on2.vp9")) {
                    c2 = 5;
                    break;
                }
                c2 = 65535;
                break;
            default:
                c2 = 65535;
                break;
        }
        switch (c2) {
            case 0:
            case 2:
            case 4:
                i4 = i2 * i3;
                i5 = 2;
                break;
            case 1:
            case 5:
                i4 = i2 * i3;
                break;
            case 3:
                String str2 = C2344d0.f6038d;
                if (!"BRAVIA 4K 2015".equals(str2) && (!"Amazon".equals(C2344d0.f6037c) || (!"KFSOWI".equals(str2) && (!"AFTS".equals(str2) || !c2072e.f4285f)))) {
                    i4 = C2344d0.m2327e(i3, 16) * C2344d0.m2327e(i2, 16) * 16 * 16;
                    i5 = 2;
                    break;
                }
                break;
        }
        return -1;
    }

    /* renamed from: t0 */
    public static List<C2072e> m2617t0(InterfaceC2074g interfaceC2074g, Format format, boolean z, boolean z2) {
        Pair<Integer, Integer> m1691c;
        String str = format.f9245l;
        if (str == null) {
            return Collections.emptyList();
        }
        List<C2072e> mo1688b = interfaceC2074g.mo1688b(str, z, z2);
        Pattern pattern = C2075h.f4352a;
        ArrayList arrayList = new ArrayList(mo1688b);
        C2075h.m1697i(arrayList, new C2070c(format));
        if ("video/dolby-vision".equals(str) && (m1691c = C2075h.m1691c(format)) != null) {
            int intValue = ((Integer) m1691c.first).intValue();
            if (intValue == 16 || intValue == 256) {
                arrayList.addAll(interfaceC2074g.mo1688b("video/hevc", z, z2));
            } else if (intValue == 512) {
                arrayList.addAll(interfaceC2074g.mo1688b("video/avc", z, z2));
            }
        }
        return Collections.unmodifiableList(arrayList);
    }

    /* renamed from: u0 */
    public static int m2618u0(C2072e c2072e, Format format) {
        if (format.f9246m == -1) {
            return m2616s0(c2072e, format.f9245l, format.f9250q, format.f9251r);
        }
        int size = format.f9247n.size();
        int i2 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            i2 += format.f9247n.get(i3).length;
        }
        return format.f9246m + i2;
    }

    /* renamed from: v0 */
    public static boolean m2619v0(long j2) {
        return j2 < -30000;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: A */
    public void mo1301A() {
        this.f6205Q0 = 0;
        this.f6204P0 = SystemClock.elapsedRealtime();
        this.f6208T0 = SystemClock.elapsedRealtime() * 1000;
    }

    /* renamed from: A0 */
    public final void m2620A0(long j2, long j3, Format format, MediaFormat mediaFormat) {
        InterfaceC2382n interfaceC2382n = this.f6226l1;
        if (interfaceC2382n != null) {
            interfaceC2382n.mo2176c(j2, j3, format, mediaFormat);
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: B */
    public void mo1302B() {
        this.f6203O0 = -9223372036854775807L;
        m2632w0();
    }

    /* renamed from: B0 */
    public void m2621B0(long j2) {
        Format m2304e = this.f4343w.m2304e(j2);
        if (m2304e != null) {
            this.f4290B = m2304e;
        }
        if (m2304e != null) {
            m2622C0(this.f4297I, m2304e.f9250q, m2304e.f9251r);
        }
        m2634y0();
        m2633x0();
        mo1311a0(j2);
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: C */
    public void mo1303C(Format[] formatArr, long j2) {
        if (this.f6224j1 == -9223372036854775807L) {
            this.f6224j1 = j2;
            return;
        }
        int i2 = this.f6225k1;
        long[] jArr = this.f6193E0;
        if (i2 == jArr.length) {
            long j3 = jArr[i2 - 1];
        } else {
            this.f6225k1 = i2 + 1;
        }
        int i3 = this.f6225k1 - 1;
        jArr[i3] = j2;
        this.f6194F0[i3] = this.f6223i1;
    }

    /* renamed from: C0 */
    public final void m2622C0(MediaCodec mediaCodec, int i2, int i3) {
        this.f6212X0 = i2;
        this.f6213Y0 = i3;
        float f2 = this.f6210V0;
        this.f6215a1 = f2;
        if (C2344d0.f6035a >= 21) {
            int i4 = this.f6209U0;
            if (i4 == 90 || i4 == 270) {
                this.f6212X0 = i3;
                this.f6213Y0 = i2;
                this.f6215a1 = 1.0f / f2;
            }
        } else {
            this.f6214Z0 = this.f6209U0;
        }
        mediaCodec.setVideoScalingMode(this.f6200L0);
    }

    /* renamed from: D0 */
    public void m2623D0(MediaCodec mediaCodec, int i2) {
        m2634y0();
        C2354n.m2488k("releaseOutputBuffer");
        mediaCodec.releaseOutputBuffer(i2, true);
        C2354n.m2443X();
        this.f6208T0 = SystemClock.elapsedRealtime() * 1000;
        this.f4341u0.f3300e++;
        this.f6206R0 = 0;
        m2633x0();
    }

    @TargetApi(21)
    /* renamed from: E0 */
    public void m2624E0(MediaCodec mediaCodec, int i2, long j2) {
        m2634y0();
        C2354n.m2488k("releaseOutputBuffer");
        mediaCodec.releaseOutputBuffer(i2, j2);
        C2354n.m2443X();
        this.f6208T0 = SystemClock.elapsedRealtime() * 1000;
        this.f4341u0.f3300e++;
        this.f6206R0 = 0;
        m2633x0();
    }

    /* renamed from: F0 */
    public final void m2625F0() {
        this.f6203O0 = this.f6190B0 > 0 ? SystemClock.elapsedRealtime() + this.f6190B0 : -9223372036854775807L;
    }

    /* renamed from: G0 */
    public final boolean m2626G0(C2072e c2072e) {
        return C2344d0.f6035a >= 23 && !this.f6220f1 && !m2631r0(c2072e.f4280a) && (!c2072e.f4285f || DummySurface.m4129e(this.f6227y0));
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: H */
    public int mo1304H(MediaCodec mediaCodec, C2072e c2072e, Format format, Format format2) {
        if (!c2072e.m1659f(format, format2, true)) {
            return 0;
        }
        int i2 = format2.f9250q;
        a aVar = this.f6195G0;
        if (i2 > aVar.f6229a || format2.f9251r > aVar.f6230b || m2618u0(c2072e, format2) > this.f6195G0.f6231c) {
            return 0;
        }
        return format.m4041N(format2) ? 3 : 2;
    }

    /* renamed from: H0 */
    public void m2627H0(MediaCodec mediaCodec, int i2) {
        C2354n.m2488k("skipVideoBuffer");
        mediaCodec.releaseOutputBuffer(i2, false);
        C2354n.m2443X();
        this.f4341u0.f3301f++;
    }

    /* JADX WARN: Code restructure failed: missing block: B:104:0x00f7, code lost:
    
        if (r11 == false) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x00f9, code lost:
    
        r10 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x00fc, code lost:
    
        if (r11 == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x0100, code lost:
    
        r4 = new android.graphics.Point(r10, r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x00ff, code lost:
    
        r5 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x00fb, code lost:
    
        r10 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x0114, code lost:
    
        r22 = r5;
     */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0165  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x01cf  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x01e2  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x01f2  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0200  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x01ef  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x011a  */
    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: I */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1305I(p005b.p199l.p200a.p201a.p219g1.C2072e r24, android.media.MediaCodec r25, com.google.android.exoplayer2.Format r26, @androidx.annotation.Nullable android.media.MediaCrypto r27, float r28) {
        /*
            Method dump skipped, instructions count: 559
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p251q1.C2379k.mo1305I(b.l.a.a.g1.e, android.media.MediaCodec, com.google.android.exoplayer2.Format, android.media.MediaCrypto, float):void");
    }

    /* renamed from: I0 */
    public void m2628I0(int i2) {
        C1944d c1944d = this.f4341u0;
        c1944d.f3302g += i2;
        this.f6205Q0 += i2;
        int i3 = this.f6206R0 + i2;
        this.f6206R0 = i3;
        c1944d.f3303h = Math.max(i3, c1944d.f3303h);
        int i4 = this.f6191C0;
        if (i4 <= 0 || this.f6205Q0 < i4) {
            return;
        }
        m2632w0();
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    @CallSuper
    /* renamed from: O */
    public boolean mo1668O() {
        try {
            return super.mo1668O();
        } finally {
            this.f6207S0 = 0;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: Q */
    public boolean mo1670Q() {
        return this.f6220f1 && C2344d0.f6035a < 23;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: R */
    public float mo1306R(float f2, Format format, Format[] formatArr) {
        float f3 = -1.0f;
        for (Format format2 : formatArr) {
            float f4 = format2.f9252s;
            if (f4 != -1.0f) {
                f3 = Math.max(f3, f4);
            }
        }
        if (f3 == -1.0f) {
            return -1.0f;
        }
        return f3 * f2;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: S */
    public List<C2072e> mo1307S(InterfaceC2074g interfaceC2074g, Format format, boolean z) {
        return m2617t0(interfaceC2074g, format, z, this.f6220f1);
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: T */
    public void mo1671T(C1945e c1945e) {
        if (this.f6197I0) {
            ByteBuffer byteBuffer = c1945e.f3308g;
            Objects.requireNonNull(byteBuffer);
            if (byteBuffer.remaining() >= 7) {
                byte b2 = byteBuffer.get();
                short s = byteBuffer.getShort();
                short s2 = byteBuffer.getShort();
                byte b3 = byteBuffer.get();
                byte b4 = byteBuffer.get();
                byteBuffer.position(0);
                if (b2 == -75 && s == 60 && s2 == 1 && b3 == 4 && b4 == 0) {
                    byte[] bArr = new byte[byteBuffer.remaining()];
                    byteBuffer.get(bArr);
                    byteBuffer.position(0);
                    MediaCodec mediaCodec = this.f4297I;
                    Bundle bundle = new Bundle();
                    bundle.putByteArray("hdr10-plus-info", bArr);
                    mediaCodec.setParameters(bundle);
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: X */
    public void mo1308X(final String str, final long j2, final long j3) {
        final InterfaceC2386r.a aVar = this.f6189A0;
        Handler handler = aVar.f6268a;
        if (handler != null) {
            handler.post(new Runnable() { // from class: b.l.a.a.q1.d
                @Override // java.lang.Runnable
                public final void run() {
                    InterfaceC2386r.a aVar2 = InterfaceC2386r.a.this;
                    String str2 = str;
                    long j4 = j2;
                    long j5 = j3;
                    InterfaceC2386r interfaceC2386r = aVar2.f6269b;
                    int i2 = C2344d0.f6035a;
                    interfaceC2386r.onVideoDecoderInitialized(str2, j4, j5);
                }
            });
        }
        this.f6196H0 = m2631r0(str);
        C2072e c2072e = this.f4302N;
        Objects.requireNonNull(c2072e);
        boolean z = false;
        if (C2344d0.f6035a >= 29 && "video/x-vnd.on2.vp9".equals(c2072e.f4281b)) {
            MediaCodecInfo.CodecProfileLevel[] m1656c = c2072e.m1656c();
            int length = m1656c.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    break;
                }
                if (m1656c[i2].profile == 16384) {
                    z = true;
                    break;
                }
                i2++;
            }
        }
        this.f6197I0 = z;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: Y */
    public void mo1309Y(C1964f0 c1964f0) {
        super.mo1309Y(c1964f0);
        final Format format = c1964f0.f3394c;
        final InterfaceC2386r.a aVar = this.f6189A0;
        Handler handler = aVar.f6268a;
        if (handler != null) {
            handler.post(new Runnable() { // from class: b.l.a.a.q1.a
                @Override // java.lang.Runnable
                public final void run() {
                    InterfaceC2386r.a aVar2 = InterfaceC2386r.a.this;
                    Format format2 = format;
                    InterfaceC2386r interfaceC2386r = aVar2.f6269b;
                    int i2 = C2344d0.f6035a;
                    interfaceC2386r.onVideoInputFormatChanged(format2);
                }
            });
        }
        this.f6210V0 = format.f9254u;
        this.f6209U0 = format.f9253t;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: Z */
    public void mo1310Z(MediaCodec mediaCodec, MediaFormat mediaFormat) {
        this.f6211W0 = mediaFormat;
        boolean z = mediaFormat.containsKey("crop-right") && mediaFormat.containsKey("crop-left") && mediaFormat.containsKey("crop-bottom") && mediaFormat.containsKey("crop-top");
        m2622C0(mediaCodec, z ? (mediaFormat.getInteger("crop-right") - mediaFormat.getInteger("crop-left")) + 1 : mediaFormat.getInteger("width"), z ? (mediaFormat.getInteger("crop-bottom") - mediaFormat.getInteger("crop-top")) + 1 : mediaFormat.getInteger("height"));
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    @CallSuper
    /* renamed from: a0 */
    public void mo1311a0(long j2) {
        if (!this.f6220f1) {
            this.f6207S0--;
        }
        while (true) {
            int i2 = this.f6225k1;
            if (i2 == 0 || j2 < this.f6194F0[0]) {
                return;
            }
            long[] jArr = this.f6193E0;
            this.f6224j1 = jArr[0];
            int i3 = i2 - 1;
            this.f6225k1 = i3;
            System.arraycopy(jArr, 1, jArr, 0, i3);
            long[] jArr2 = this.f6194F0;
            System.arraycopy(jArr2, 1, jArr2, 0, this.f6225k1);
            m2629p0();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    @CallSuper
    /* renamed from: b0 */
    public void mo1313b0(C1945e c1945e) {
        if (!this.f6220f1) {
            this.f6207S0++;
        }
        this.f6223i1 = Math.max(c1945e.f3307f, this.f6223i1);
        if (C2344d0.f6035a >= 23 || !this.f6220f1) {
            return;
        }
        m2621B0(c1945e.f3307f);
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0075, code lost:
    
        if ((m2619v0(r13) && r10 > 100000) != false) goto L35;
     */
    /* JADX WARN: Removed duplicated region for block: B:104:0x01c3  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x007e  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0127  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x015f  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x016b  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x01a3  */
    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: d0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean mo1315d0(long r25, long r27, android.media.MediaCodec r29, java.nio.ByteBuffer r30, int r31, int r32, long r33, boolean r35, boolean r36, com.google.android.exoplayer2.Format r37) {
        /*
            Method dump skipped, instructions count: 536
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p251q1.C2379k.mo1315d0(long, long, android.media.MediaCodec, java.nio.ByteBuffer, int, int, long, boolean, boolean, com.google.android.exoplayer2.Format):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    @CallSuper
    /* renamed from: f0 */
    public void mo1677f0() {
        try {
            super.mo1677f0();
        } finally {
            this.f6207S0 = 0;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.InterfaceC2396t0
    public boolean isReady() {
        Surface surface;
        if (super.isReady() && (this.f6201M0 || (((surface = this.f6199K0) != null && this.f6198J0 == surface) || this.f4297I == null || this.f6220f1))) {
            this.f6203O0 = -9223372036854775807L;
            return true;
        }
        if (this.f6203O0 == -9223372036854775807L) {
            return false;
        }
        if (SystemClock.elapsedRealtime() < this.f6203O0) {
            return true;
        }
        this.f6203O0 = -9223372036854775807L;
        return false;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u, p005b.p199l.p200a.p201a.C2392r0.b
    /* renamed from: k */
    public void mo1318k(int i2, @Nullable Object obj) {
        if (i2 != 1) {
            if (i2 != 4) {
                if (i2 == 6) {
                    this.f6226l1 = (InterfaceC2382n) obj;
                    return;
                }
                return;
            } else {
                int intValue = ((Integer) obj).intValue();
                this.f6200L0 = intValue;
                MediaCodec mediaCodec = this.f4297I;
                if (mediaCodec != null) {
                    mediaCodec.setVideoScalingMode(intValue);
                    return;
                }
                return;
            }
        }
        Surface surface = (Surface) obj;
        if (surface == null) {
            Surface surface2 = this.f6199K0;
            if (surface2 != null) {
                surface = surface2;
            } else {
                C2072e c2072e = this.f4302N;
                if (c2072e != null && m2626G0(c2072e)) {
                    surface = DummySurface.m4130k(this.f6227y0, c2072e.f4285f);
                    this.f6199K0 = surface;
                }
            }
        }
        if (this.f6198J0 == surface) {
            if (surface == null || surface == this.f6199K0) {
                return;
            }
            m2635z0();
            if (this.f6201M0) {
                InterfaceC2386r.a aVar = this.f6189A0;
                Surface surface3 = this.f6198J0;
                Handler handler = aVar.f6268a;
                if (handler != null) {
                    handler.post(new RunnableC2373e(aVar, surface3));
                    return;
                }
                return;
            }
            return;
        }
        this.f6198J0 = surface;
        int i3 = this.f6318h;
        MediaCodec mediaCodec2 = this.f4297I;
        if (mediaCodec2 != null) {
            if (C2344d0.f6035a < 23 || surface == null || this.f6196H0) {
                mo1677f0();
                m1673V();
            } else {
                mediaCodec2.setOutputSurface(surface);
            }
        }
        if (surface == null || surface == this.f6199K0) {
            m2630q0();
            m2629p0();
            return;
        }
        m2635z0();
        m2629p0();
        if (i3 == 2) {
            m2625F0();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: l0 */
    public boolean mo1683l0(C2072e c2072e) {
        return this.f6198J0 != null || m2626G0(c2072e);
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f
    /* renamed from: m0 */
    public int mo1319m0(InterfaceC2074g interfaceC2074g, @Nullable InterfaceC1954e<C1957h> interfaceC1954e, Format format) {
        int i2 = 0;
        if (!C2357q.m2547j(format.f9245l)) {
            return 0;
        }
        DrmInitData drmInitData = format.f9248o;
        boolean z = drmInitData != null;
        List<C2072e> m2617t0 = m2617t0(interfaceC2074g, format, z, false);
        if (z && m2617t0.isEmpty()) {
            m2617t0 = m2617t0(interfaceC2074g, format, false, false);
        }
        if (m2617t0.isEmpty()) {
            return 1;
        }
        if (!(drmInitData == null || C1957h.class.equals(format.f9235F) || (format.f9235F == null && AbstractC2397u.m2664F(interfaceC1954e, drmInitData)))) {
            return 2;
        }
        C2072e c2072e = m2617t0.get(0);
        boolean m1657d = c2072e.m1657d(format);
        int i3 = c2072e.m1658e(format) ? 16 : 8;
        if (m1657d) {
            List<C2072e> m2617t02 = m2617t0(interfaceC2074g, format, z, true);
            if (!m2617t02.isEmpty()) {
                C2072e c2072e2 = m2617t02.get(0);
                if (c2072e2.m1657d(format) && c2072e2.m1658e(format)) {
                    i2 = 32;
                }
            }
        }
        return (m1657d ? 4 : 3) | i3 | i2;
    }

    /* renamed from: p0 */
    public final void m2629p0() {
        MediaCodec mediaCodec;
        this.f6201M0 = false;
        if (C2344d0.f6035a < 23 || !this.f6220f1 || (mediaCodec = this.f4297I) == null) {
            return;
        }
        this.f6222h1 = new b(mediaCodec);
    }

    /* renamed from: q0 */
    public final void m2630q0() {
        this.f6216b1 = -1;
        this.f6217c1 = -1;
        this.f6219e1 = -1.0f;
        this.f6218d1 = -1;
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x0653 A[ADDED_TO_REGION] */
    /* renamed from: r0 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean m2631r0(java.lang.String r8) {
        /*
            Method dump skipped, instructions count: 2398
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p251q1.C2379k.m2631r0(java.lang.String):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: w */
    public void mo1325w() {
        this.f6223i1 = -9223372036854775807L;
        this.f6224j1 = -9223372036854775807L;
        this.f6225k1 = 0;
        this.f6211W0 = null;
        m2630q0();
        m2629p0();
        C2383o c2383o = this.f6228z0;
        if (c2383o.f6248a != null) {
            C2383o.a aVar = c2383o.f6250c;
            if (aVar != null) {
                aVar.f6260a.unregisterDisplayListener(aVar);
            }
            c2383o.f6249b.f6264f.sendEmptyMessage(2);
        }
        this.f6222h1 = null;
        try {
            super.mo1325w();
            final InterfaceC2386r.a aVar2 = this.f6189A0;
            final C1944d c1944d = this.f4341u0;
            Objects.requireNonNull(aVar2);
            synchronized (c1944d) {
            }
            Handler handler = aVar2.f6268a;
            if (handler != null) {
                handler.post(new Runnable() { // from class: b.l.a.a.q1.f
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2386r.a aVar3 = InterfaceC2386r.a.this;
                        C1944d c1944d2 = c1944d;
                        Objects.requireNonNull(aVar3);
                        synchronized (c1944d2) {
                        }
                        InterfaceC2386r interfaceC2386r = aVar3.f6269b;
                        int i2 = C2344d0.f6035a;
                        interfaceC2386r.onVideoDisabled(c1944d2);
                    }
                });
            }
        } catch (Throwable th) {
            final InterfaceC2386r.a aVar3 = this.f6189A0;
            final C1944d c1944d2 = this.f4341u0;
            Objects.requireNonNull(aVar3);
            synchronized (c1944d2) {
                Handler handler2 = aVar3.f6268a;
                if (handler2 != null) {
                    handler2.post(new Runnable() { // from class: b.l.a.a.q1.f
                        @Override // java.lang.Runnable
                        public final void run() {
                            InterfaceC2386r.a aVar32 = InterfaceC2386r.a.this;
                            C1944d c1944d22 = c1944d2;
                            Objects.requireNonNull(aVar32);
                            synchronized (c1944d22) {
                            }
                            InterfaceC2386r interfaceC2386r = aVar32.f6269b;
                            int i2 = C2344d0.f6035a;
                            interfaceC2386r.onVideoDisabled(c1944d22);
                        }
                    });
                }
                throw th;
            }
        }
    }

    /* renamed from: w0 */
    public final void m2632w0() {
        if (this.f6205Q0 > 0) {
            long elapsedRealtime = SystemClock.elapsedRealtime();
            final long j2 = elapsedRealtime - this.f6204P0;
            final InterfaceC2386r.a aVar = this.f6189A0;
            final int i2 = this.f6205Q0;
            Handler handler = aVar.f6268a;
            if (handler != null) {
                handler.post(new Runnable() { // from class: b.l.a.a.q1.c
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2386r.a aVar2 = InterfaceC2386r.a.this;
                        int i3 = i2;
                        long j3 = j2;
                        InterfaceC2386r interfaceC2386r = aVar2.f6269b;
                        int i4 = C2344d0.f6035a;
                        interfaceC2386r.onDroppedFrames(i3, j3);
                    }
                });
            }
            this.f6205Q0 = 0;
            this.f6204P0 = elapsedRealtime;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: x */
    public void mo1326x(boolean z) {
        super.mo1326x(z);
        int i2 = this.f6221g1;
        int i3 = this.f6316f.f6326b;
        this.f6221g1 = i3;
        this.f6220f1 = i3 != 0;
        if (i3 != i2) {
            mo1677f0();
        }
        final InterfaceC2386r.a aVar = this.f6189A0;
        final C1944d c1944d = this.f4341u0;
        Handler handler = aVar.f6268a;
        if (handler != null) {
            handler.post(new Runnable() { // from class: b.l.a.a.q1.b
                @Override // java.lang.Runnable
                public final void run() {
                    InterfaceC2386r.a aVar2 = InterfaceC2386r.a.this;
                    C1944d c1944d2 = c1944d;
                    InterfaceC2386r interfaceC2386r = aVar2.f6269b;
                    int i4 = C2344d0.f6035a;
                    interfaceC2386r.onVideoEnabled(c1944d2);
                }
            });
        }
        C2383o c2383o = this.f6228z0;
        c2383o.f6256i = false;
        if (c2383o.f6248a != null) {
            c2383o.f6249b.f6264f.sendEmptyMessage(1);
            C2383o.a aVar2 = c2383o.f6250c;
            if (aVar2 != null) {
                aVar2.f6260a.registerDisplayListener(aVar2, null);
            }
            c2383o.m2638b();
        }
    }

    /* renamed from: x0 */
    public void m2633x0() {
        if (this.f6201M0) {
            return;
        }
        this.f6201M0 = true;
        InterfaceC2386r.a aVar = this.f6189A0;
        Surface surface = this.f6198J0;
        Handler handler = aVar.f6268a;
        if (handler != null) {
            handler.post(new RunnableC2373e(aVar, surface));
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: y */
    public void mo1327y(long j2, boolean z) {
        this.f4329o0 = false;
        this.f4331p0 = false;
        this.f4339t0 = false;
        m1667N();
        this.f4343w.m2301b();
        m2629p0();
        this.f6202N0 = -9223372036854775807L;
        this.f6206R0 = 0;
        this.f6223i1 = -9223372036854775807L;
        int i2 = this.f6225k1;
        if (i2 != 0) {
            this.f6224j1 = this.f6193E0[i2 - 1];
            this.f6225k1 = 0;
        }
        if (z) {
            m2625F0();
        } else {
            this.f6203O0 = -9223372036854775807L;
        }
    }

    /* renamed from: y0 */
    public final void m2634y0() {
        int i2 = this.f6212X0;
        if (i2 == -1 && this.f6213Y0 == -1) {
            return;
        }
        if (this.f6216b1 == i2 && this.f6217c1 == this.f6213Y0 && this.f6218d1 == this.f6214Z0 && this.f6219e1 == this.f6215a1) {
            return;
        }
        this.f6189A0.m2642a(i2, this.f6213Y0, this.f6214Z0, this.f6215a1);
        this.f6216b1 = this.f6212X0;
        this.f6217c1 = this.f6213Y0;
        this.f6218d1 = this.f6214Z0;
        this.f6219e1 = this.f6215a1;
    }

    @Override // p005b.p199l.p200a.p201a.p219g1.AbstractC2073f, p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: z */
    public void mo1328z() {
        try {
            super.mo1328z();
            Surface surface = this.f6199K0;
            if (surface != null) {
                if (this.f6198J0 == surface) {
                    this.f6198J0 = null;
                }
                surface.release();
                this.f6199K0 = null;
            }
        } catch (Throwable th) {
            if (this.f6199K0 != null) {
                Surface surface2 = this.f6198J0;
                Surface surface3 = this.f6199K0;
                if (surface2 == surface3) {
                    this.f6198J0 = null;
                }
                surface3.release();
                this.f6199K0 = null;
            }
            throw th;
        }
    }

    /* renamed from: z0 */
    public final void m2635z0() {
        int i2 = this.f6216b1;
        if (i2 == -1 && this.f6217c1 == -1) {
            return;
        }
        this.f6189A0.m2642a(i2, this.f6217c1, this.f6218d1, this.f6219e1);
    }
}
