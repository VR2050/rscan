package p005b.p199l.p200a.p201a.p219g1;

import android.annotation.TargetApi;
import android.graphics.Point;
import android.media.MediaCodecInfo;
import android.util.Pair;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.g1.e */
/* loaded from: classes.dex */
public final class C2072e {

    /* renamed from: a */
    public final String f4280a;

    /* renamed from: b */
    @Nullable
    public final String f4281b;

    /* renamed from: c */
    @Nullable
    public final String f4282c;

    /* renamed from: d */
    @Nullable
    public final MediaCodecInfo.CodecCapabilities f4283d;

    /* renamed from: e */
    public final boolean f4284e;

    /* renamed from: f */
    public final boolean f4285f;

    /* renamed from: g */
    public final boolean f4286g;

    /* renamed from: h */
    public final boolean f4287h;

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0043, code lost:
    
        if (r4 == null) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0047, code lost:
    
        if (p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a < 21) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x004f, code lost:
    
        if (r4.isFeatureSupported("secure-playback") == false) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0051, code lost:
    
        r4 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0054, code lost:
    
        if (r4 == false) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0053, code lost:
    
        r4 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0057, code lost:
    
        r1 = false;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2072e(java.lang.String r1, @androidx.annotation.Nullable java.lang.String r2, @androidx.annotation.Nullable java.lang.String r3, @androidx.annotation.Nullable android.media.MediaCodecInfo.CodecCapabilities r4, boolean r5, boolean r6, boolean r7, boolean r8, boolean r9, boolean r10) {
        /*
            r0 = this;
            r0.<init>()
            java.util.Objects.requireNonNull(r1)
            r0.f4280a = r1
            r0.f4281b = r2
            r0.f4282c = r3
            r0.f4283d = r4
            r0.f4286g = r5
            r1 = 1
            r3 = 0
            if (r9 != 0) goto L2b
            if (r4 == 0) goto L2b
            int r5 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            r6 = 19
            if (r5 < r6) goto L26
            java.lang.String r5 = "adaptive-playback"
            boolean r5 = r4.isFeatureSupported(r5)
            if (r5 == 0) goto L26
            r5 = 1
            goto L27
        L26:
            r5 = 0
        L27:
            if (r5 == 0) goto L2b
            r5 = 1
            goto L2c
        L2b:
            r5 = 0
        L2c:
            r0.f4284e = r5
            r5 = 21
            if (r4 == 0) goto L41
            int r6 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            if (r6 < r5) goto L40
            java.lang.String r6 = "tunneled-playback"
            boolean r6 = r4.isFeatureSupported(r6)
            if (r6 == 0) goto L40
            r6 = 1
            goto L41
        L40:
            r6 = 0
        L41:
            if (r10 != 0) goto L58
            if (r4 == 0) goto L57
            int r6 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            if (r6 < r5) goto L53
            java.lang.String r5 = "secure-playback"
            boolean r4 = r4.isFeatureSupported(r5)
            if (r4 == 0) goto L53
            r4 = 1
            goto L54
        L53:
            r4 = 0
        L54:
            if (r4 == 0) goto L57
            goto L58
        L57:
            r1 = 0
        L58:
            r0.f4285f = r1
            boolean r1 = p005b.p199l.p200a.p201a.p250p1.C2357q.m2547j(r2)
            r0.f4287h = r1
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.C2072e.<init>(java.lang.String, java.lang.String, java.lang.String, android.media.MediaCodecInfo$CodecCapabilities, boolean, boolean, boolean, boolean, boolean, boolean):void");
    }

    @TargetApi(21)
    /* renamed from: a */
    public static Point m1653a(MediaCodecInfo.VideoCapabilities videoCapabilities, int i2, int i3) {
        int widthAlignment = videoCapabilities.getWidthAlignment();
        int heightAlignment = videoCapabilities.getHeightAlignment();
        return new Point(C2344d0.m2327e(i2, widthAlignment) * widthAlignment, C2344d0.m2327e(i3, heightAlignment) * heightAlignment);
    }

    @TargetApi(21)
    /* renamed from: b */
    public static boolean m1654b(MediaCodecInfo.VideoCapabilities videoCapabilities, int i2, int i3, double d2) {
        Point m1653a = m1653a(videoCapabilities, i2, i3);
        int i4 = m1653a.x;
        int i5 = m1653a.y;
        return (d2 == -1.0d || d2 <= ShadowDrawableWrapper.COS_45) ? videoCapabilities.isSizeSupported(i4, i5) : videoCapabilities.areSizeAndRateSupported(i4, i5, Math.floor(d2));
    }

    /* renamed from: h */
    public static C2072e m1655h(String str, String str2, String str3, @Nullable MediaCodecInfo.CodecCapabilities codecCapabilities, boolean z, boolean z2, boolean z3, boolean z4, boolean z5) {
        return new C2072e(str, str2, str3, codecCapabilities, false, z, z2, z3, z4, z5);
    }

    /* renamed from: c */
    public MediaCodecInfo.CodecProfileLevel[] m1656c() {
        MediaCodecInfo.CodecProfileLevel[] codecProfileLevelArr;
        MediaCodecInfo.CodecCapabilities codecCapabilities = this.f4283d;
        return (codecCapabilities == null || (codecProfileLevelArr = codecCapabilities.profileLevels) == null) ? new MediaCodecInfo.CodecProfileLevel[0] : codecProfileLevelArr;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x005a A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:40:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:55:? A[RETURN, SYNTHETIC] */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean m1657d(com.google.android.exoplayer2.Format r10) {
        /*
            Method dump skipped, instructions count: 332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.C2072e.m1657d(com.google.android.exoplayer2.Format):boolean");
    }

    /* renamed from: e */
    public boolean m1658e(Format format) {
        if (this.f4287h) {
            return this.f4284e;
        }
        Pair<Integer, Integer> m1691c = C2075h.m1691c(format);
        return m1691c != null && ((Integer) m1691c.first).intValue() == 42;
    }

    /* renamed from: f */
    public boolean m1659f(Format format, Format format2, boolean z) {
        if (this.f4287h) {
            return format.f9245l.equals(format2.f9245l) && format.f9253t == format2.f9253t && (this.f4284e || (format.f9250q == format2.f9250q && format.f9251r == format2.f9251r)) && ((!z && format2.f9257x == null) || C2344d0.m2323a(format.f9257x, format2.f9257x));
        }
        if ("audio/mp4a-latm".equals(this.f4281b) && format.f9245l.equals(format2.f9245l) && format.f9258y == format2.f9258y && format.f9259z == format2.f9259z) {
            Pair<Integer, Integer> m1691c = C2075h.m1691c(format);
            Pair<Integer, Integer> m1691c2 = C2075h.m1691c(format2);
            if (m1691c != null && m1691c2 != null) {
                return ((Integer) m1691c.first).intValue() == 42 && ((Integer) m1691c2.first).intValue() == 42;
            }
        }
        return false;
    }

    @TargetApi(21)
    /* renamed from: g */
    public boolean m1660g(int i2, int i3, double d2) {
        MediaCodecInfo.CodecCapabilities codecCapabilities = this.f4283d;
        if (codecCapabilities == null) {
            String str = C2344d0.f6039e;
            return false;
        }
        MediaCodecInfo.VideoCapabilities videoCapabilities = codecCapabilities.getVideoCapabilities();
        if (videoCapabilities == null) {
            String str2 = C2344d0.f6039e;
            return false;
        }
        if (!m1654b(videoCapabilities, i2, i3, d2)) {
            if (i2 < i3) {
                if ((("OMX.MTK.VIDEO.DECODER.HEVC".equals(this.f4280a) && "mcv5a".equals(C2344d0.f6036b)) ? false : true) && m1654b(videoCapabilities, i3, i2, d2)) {
                    String str3 = C2344d0.f6039e;
                }
            }
            String str4 = C2344d0.f6039e;
            return false;
        }
        return true;
    }

    public String toString() {
        return this.f4280a;
    }
}
