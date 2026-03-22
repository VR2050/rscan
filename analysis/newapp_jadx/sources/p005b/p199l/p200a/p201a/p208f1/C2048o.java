package p005b.p199l.p200a.p201a.p208f1;

import androidx.annotation.Nullable;
import com.luck.picture.lib.config.PictureMimeType;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.a.a.f1.o */
/* loaded from: classes.dex */
public final class C2048o {

    /* renamed from: a */
    public static final String[] f4173a = {"audio/mpeg-L1", "audio/mpeg-L2", PictureMimeType.MIME_TYPE_AUDIO};

    /* renamed from: b */
    public static final int[] f4174b = {44100, 48000, 32000};

    /* renamed from: c */
    public static final int[] f4175c = {32000, 64000, 96000, 128000, 160000, 192000, 224000, 256000, 288000, 320000, 352000, 384000, 416000, 448000};

    /* renamed from: d */
    public static final int[] f4176d = {32000, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 144000, 160000, 176000, 192000, 224000, 256000};

    /* renamed from: e */
    public static final int[] f4177e = {32000, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 160000, 192000, 224000, 256000, 320000, 384000};

    /* renamed from: f */
    public static final int[] f4178f = {32000, 40000, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 160000, 192000, 224000, 256000, 320000};

    /* renamed from: g */
    public static final int[] f4179g = {8000, 16000, 24000, 32000, 40000, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 144000, 160000};

    /* renamed from: h */
    public int f4180h;

    /* renamed from: i */
    @Nullable
    public String f4181i;

    /* renamed from: j */
    public int f4182j;

    /* renamed from: k */
    public int f4183k;

    /* renamed from: l */
    public int f4184l;

    /* renamed from: m */
    public int f4185m;

    /* renamed from: n */
    public int f4186n;

    /* renamed from: a */
    public static int m1633a(int i2) {
        int i3;
        int i4;
        int i5;
        int i6;
        if (!m1635c(i2) || (i3 = (i2 >>> 19) & 3) == 1 || (i4 = (i2 >>> 17) & 3) == 0 || (i5 = (i2 >>> 12) & 15) == 0 || i5 == 15 || (i6 = (i2 >>> 10) & 3) == 3) {
            return -1;
        }
        int i7 = f4174b[i6];
        if (i3 == 2) {
            i7 /= 2;
        } else if (i3 == 0) {
            i7 /= 4;
        }
        int i8 = (i2 >>> 9) & 1;
        if (i4 == 3) {
            return ((((i3 == 3 ? f4175c[i5 - 1] : f4176d[i5 - 1]) * 12) / i7) + i8) * 4;
        }
        int i9 = i3 == 3 ? i4 == 2 ? f4177e[i5 - 1] : f4178f[i5 - 1] : f4179g[i5 - 1];
        int i10 = IjkMediaMeta.FF_PROFILE_H264_HIGH_444;
        if (i3 == 3) {
            return ((i9 * IjkMediaMeta.FF_PROFILE_H264_HIGH_444) / i7) + i8;
        }
        if (i4 == 1) {
            i10 = 72;
        }
        return ((i10 * i9) / i7) + i8;
    }

    /* renamed from: b */
    public static int m1634b(int i2, int i3) {
        if (i3 == 1) {
            return i2 == 3 ? 1152 : 576;
        }
        if (i3 == 2) {
            return 1152;
        }
        if (i3 == 3) {
            return 384;
        }
        throw new IllegalArgumentException();
    }

    /* renamed from: c */
    public static boolean m1635c(int i2) {
        return (i2 & (-2097152)) == -2097152;
    }

    /* renamed from: d */
    public static boolean m1636d(int i2, C2048o c2048o) {
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        if (!m1635c(i2) || (i3 = (i2 >>> 19) & 3) == 1 || (i4 = (i2 >>> 17) & 3) == 0 || (i5 = (i2 >>> 12) & 15) == 0 || i5 == 15 || (i6 = (i2 >>> 10) & 3) == 3) {
            return false;
        }
        int i10 = f4174b[i6];
        if (i3 == 2) {
            i10 /= 2;
        } else if (i3 == 0) {
            i10 /= 4;
        }
        int i11 = (i2 >>> 9) & 1;
        int m1634b = m1634b(i3, i4);
        if (i4 == 3) {
            i7 = i3 == 3 ? f4175c[i5 - 1] : f4176d[i5 - 1];
            i9 = (((i7 * 12) / i10) + i11) * 4;
        } else {
            if (i3 == 3) {
                i7 = i4 == 2 ? f4177e[i5 - 1] : f4178f[i5 - 1];
                i8 = (i7 * IjkMediaMeta.FF_PROFILE_H264_HIGH_444) / i10;
            } else {
                i7 = f4179g[i5 - 1];
                i8 = ((i4 == 1 ? 72 : IjkMediaMeta.FF_PROFILE_H264_HIGH_444) * i7) / i10;
            }
            i9 = i8 + i11;
        }
        String str = f4173a[3 - i4];
        int i12 = ((i2 >> 6) & 3) == 3 ? 1 : 2;
        c2048o.f4180h = i3;
        c2048o.f4181i = str;
        c2048o.f4182j = i9;
        c2048o.f4183k = i10;
        c2048o.f4184l = i12;
        c2048o.f4185m = i7;
        c2048o.f4186n = m1634b;
        return true;
    }
}
