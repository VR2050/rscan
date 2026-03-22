package p005b.p199l.p200a.p201a.p219g1;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.text.TextUtils;
import android.util.Pair;
import android.util.SparseIntArray;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.video.ColorInfo;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p219g1.C2075h;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

@SuppressLint({"InlinedApi"})
/* renamed from: b.l.a.a.g1.h */
/* loaded from: classes.dex */
public final class C2075h {

    /* renamed from: c */
    public static final SparseIntArray f4354c;

    /* renamed from: d */
    public static final SparseIntArray f4355d;

    /* renamed from: e */
    public static final SparseIntArray f4356e;

    /* renamed from: f */
    public static final SparseIntArray f4357f;

    /* renamed from: g */
    public static final Map<String, Integer> f4358g;

    /* renamed from: h */
    public static final Map<String, Integer> f4359h;

    /* renamed from: i */
    public static final Map<String, Integer> f4360i;

    /* renamed from: j */
    public static final SparseIntArray f4361j;

    /* renamed from: k */
    public static final SparseIntArray f4362k;

    /* renamed from: a */
    public static final Pattern f4352a = Pattern.compile("^\\D?(\\d+)$");

    /* renamed from: b */
    public static final HashMap<b, List<C2072e>> f4353b = new HashMap<>();

    /* renamed from: l */
    public static int f4363l = -1;

    /* renamed from: b.l.a.a.g1.h$b */
    public static final class b {

        /* renamed from: a */
        public final String f4364a;

        /* renamed from: b */
        public final boolean f4365b;

        /* renamed from: c */
        public final boolean f4366c;

        public b(String str, boolean z, boolean z2) {
            this.f4364a = str;
            this.f4365b = z;
            this.f4366c = z2;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || obj.getClass() != b.class) {
                return false;
            }
            b bVar = (b) obj;
            return TextUtils.equals(this.f4364a, bVar.f4364a) && this.f4365b == bVar.f4365b && this.f4366c == bVar.f4366c;
        }

        public int hashCode() {
            return ((C1499a.m598T(this.f4364a, 31, 31) + (this.f4365b ? 1231 : 1237)) * 31) + (this.f4366c ? 1231 : 1237);
        }
    }

    /* renamed from: b.l.a.a.g1.h$c */
    public static class c extends Exception {
        public c(Throwable th, a aVar) {
            super("Failed to query underlying media codecs", th);
        }
    }

    /* renamed from: b.l.a.a.g1.h$d */
    public interface d {
        /* renamed from: a */
        MediaCodecInfo mo1698a(int i2);

        /* renamed from: b */
        boolean mo1699b(String str, String str2, MediaCodecInfo.CodecCapabilities codecCapabilities);

        /* renamed from: c */
        boolean mo1700c(String str, String str2, MediaCodecInfo.CodecCapabilities codecCapabilities);

        /* renamed from: d */
        int mo1701d();

        /* renamed from: e */
        boolean mo1702e();
    }

    /* renamed from: b.l.a.a.g1.h$e */
    public static final class e implements d {
        public e(a aVar) {
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: a */
        public MediaCodecInfo mo1698a(int i2) {
            return MediaCodecList.getCodecInfoAt(i2);
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: b */
        public boolean mo1699b(String str, String str2, MediaCodecInfo.CodecCapabilities codecCapabilities) {
            return "secure-playback".equals(str) && "video/avc".equals(str2);
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: c */
        public boolean mo1700c(String str, String str2, MediaCodecInfo.CodecCapabilities codecCapabilities) {
            return false;
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: d */
        public int mo1701d() {
            return MediaCodecList.getCodecCount();
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: e */
        public boolean mo1702e() {
            return false;
        }
    }

    @TargetApi(21)
    /* renamed from: b.l.a.a.g1.h$f */
    public static final class f implements d {

        /* renamed from: a */
        public final int f4367a;

        /* renamed from: b */
        @Nullable
        public MediaCodecInfo[] f4368b;

        public f(boolean z, boolean z2) {
            this.f4367a = (z || z2) ? 1 : 0;
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: a */
        public MediaCodecInfo mo1698a(int i2) {
            if (this.f4368b == null) {
                this.f4368b = new MediaCodecList(this.f4367a).getCodecInfos();
            }
            return this.f4368b[i2];
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: b */
        public boolean mo1699b(String str, String str2, MediaCodecInfo.CodecCapabilities codecCapabilities) {
            return codecCapabilities.isFeatureSupported(str);
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: c */
        public boolean mo1700c(String str, String str2, MediaCodecInfo.CodecCapabilities codecCapabilities) {
            return codecCapabilities.isFeatureRequired(str);
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: d */
        public int mo1701d() {
            if (this.f4368b == null) {
                this.f4368b = new MediaCodecList(this.f4367a).getCodecInfos();
            }
            return this.f4368b.length;
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.d
        /* renamed from: e */
        public boolean mo1702e() {
            return true;
        }
    }

    /* renamed from: b.l.a.a.g1.h$g */
    public interface g<T> {
        /* renamed from: a */
        int mo1652a(T t);
    }

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        f4354c = sparseIntArray;
        sparseIntArray.put(66, 1);
        sparseIntArray.put(77, 2);
        sparseIntArray.put(88, 4);
        sparseIntArray.put(100, 8);
        sparseIntArray.put(110, 16);
        sparseIntArray.put(122, 32);
        sparseIntArray.put(IjkMediaMeta.FF_PROFILE_H264_HIGH_444_PREDICTIVE, 64);
        SparseIntArray sparseIntArray2 = new SparseIntArray();
        f4355d = sparseIntArray2;
        sparseIntArray2.put(10, 1);
        sparseIntArray2.put(11, 4);
        sparseIntArray2.put(12, 8);
        sparseIntArray2.put(13, 16);
        sparseIntArray2.put(20, 32);
        sparseIntArray2.put(21, 64);
        sparseIntArray2.put(22, 128);
        sparseIntArray2.put(30, 256);
        sparseIntArray2.put(31, 512);
        sparseIntArray2.put(32, 1024);
        sparseIntArray2.put(40, 2048);
        sparseIntArray2.put(41, 4096);
        sparseIntArray2.put(42, 8192);
        sparseIntArray2.put(50, 16384);
        sparseIntArray2.put(51, 32768);
        sparseIntArray2.put(52, 65536);
        SparseIntArray sparseIntArray3 = new SparseIntArray();
        f4356e = sparseIntArray3;
        sparseIntArray3.put(0, 1);
        sparseIntArray3.put(1, 2);
        sparseIntArray3.put(2, 4);
        sparseIntArray3.put(3, 8);
        SparseIntArray sparseIntArray4 = new SparseIntArray();
        f4357f = sparseIntArray4;
        sparseIntArray4.put(10, 1);
        sparseIntArray4.put(11, 2);
        sparseIntArray4.put(20, 4);
        sparseIntArray4.put(21, 8);
        sparseIntArray4.put(30, 16);
        sparseIntArray4.put(31, 32);
        sparseIntArray4.put(40, 64);
        sparseIntArray4.put(41, 128);
        sparseIntArray4.put(50, 256);
        sparseIntArray4.put(51, 512);
        sparseIntArray4.put(60, 2048);
        sparseIntArray4.put(61, 4096);
        sparseIntArray4.put(62, 8192);
        HashMap hashMap = new HashMap();
        f4358g = hashMap;
        hashMap.put("L30", 1);
        hashMap.put("L60", 4);
        hashMap.put("L63", 16);
        hashMap.put("L90", 64);
        hashMap.put("L93", 256);
        hashMap.put("L120", 1024);
        hashMap.put("L123", 4096);
        C1499a.m601W(16384, hashMap, "L150", 65536, "L153", 262144, "L156", 1048576, "L180");
        hashMap.put("L183", 4194304);
        hashMap.put("L186", 16777216);
        hashMap.put("H30", 2);
        hashMap.put("H60", 8);
        hashMap.put("H63", 32);
        hashMap.put("H90", 128);
        hashMap.put("H93", 512);
        hashMap.put("H120", 2048);
        hashMap.put("H123", 8192);
        C1499a.m601W(32768, hashMap, "H150", 131072, "H153", 524288, "H156", 2097152, "H180");
        hashMap.put("H183", 8388608);
        hashMap.put("H186", 33554432);
        HashMap hashMap2 = new HashMap();
        f4359h = hashMap2;
        hashMap2.put("00", 1);
        hashMap2.put("01", 2);
        hashMap2.put("02", 4);
        hashMap2.put("03", 8);
        hashMap2.put("04", 16);
        hashMap2.put("05", 32);
        hashMap2.put("06", 64);
        hashMap2.put("07", 128);
        hashMap2.put("08", 256);
        hashMap2.put("09", 512);
        HashMap hashMap3 = new HashMap();
        f4360i = hashMap3;
        hashMap3.put("01", 1);
        hashMap3.put("02", 2);
        hashMap3.put("03", 4);
        hashMap3.put("04", 8);
        hashMap3.put("05", 16);
        hashMap3.put("06", 32);
        hashMap3.put("07", 64);
        hashMap3.put("08", 128);
        hashMap3.put("09", 256);
        SparseIntArray sparseIntArray5 = new SparseIntArray();
        f4361j = sparseIntArray5;
        sparseIntArray5.put(0, 1);
        sparseIntArray5.put(1, 2);
        sparseIntArray5.put(2, 4);
        sparseIntArray5.put(3, 8);
        sparseIntArray5.put(4, 16);
        sparseIntArray5.put(5, 32);
        sparseIntArray5.put(6, 64);
        sparseIntArray5.put(7, 128);
        sparseIntArray5.put(8, 256);
        sparseIntArray5.put(9, 512);
        sparseIntArray5.put(10, 1024);
        sparseIntArray5.put(11, 2048);
        sparseIntArray5.put(12, 4096);
        sparseIntArray5.put(13, 8192);
        sparseIntArray5.put(14, 16384);
        sparseIntArray5.put(15, 32768);
        sparseIntArray5.put(16, 65536);
        sparseIntArray5.put(17, 131072);
        sparseIntArray5.put(18, 262144);
        sparseIntArray5.put(19, 524288);
        sparseIntArray5.put(20, 1048576);
        sparseIntArray5.put(21, 2097152);
        sparseIntArray5.put(22, 4194304);
        sparseIntArray5.put(23, 8388608);
        SparseIntArray sparseIntArray6 = new SparseIntArray();
        f4362k = sparseIntArray6;
        sparseIntArray6.put(1, 1);
        sparseIntArray6.put(2, 2);
        sparseIntArray6.put(3, 3);
        sparseIntArray6.put(4, 4);
        sparseIntArray6.put(5, 5);
        sparseIntArray6.put(6, 6);
        sparseIntArray6.put(17, 17);
        sparseIntArray6.put(20, 20);
        sparseIntArray6.put(23, 23);
        sparseIntArray6.put(29, 29);
        sparseIntArray6.put(39, 39);
        sparseIntArray6.put(42, 42);
    }

    /* renamed from: a */
    public static void m1689a(String str, List<C2072e> list) {
        if ("audio/raw".equals(str)) {
            if (C2344d0.f6035a < 26 && C2344d0.f6036b.equals("R9") && list.size() == 1 && list.get(0).f4280a.equals("OMX.MTK.AUDIO.DECODER.RAW")) {
                list.add(C2072e.m1655h("OMX.google.raw.decoder", "audio/raw", "audio/raw", null, false, true, false, false, false));
            }
            m1697i(list, new g() { // from class: b.l.a.a.g1.a
                @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.g
                /* renamed from: a */
                public final int mo1652a(Object obj) {
                    Pattern pattern = C2075h.f4352a;
                    String str2 = ((C2072e) obj).f4280a;
                    if (str2.startsWith("OMX.google") || str2.startsWith("c2.android")) {
                        return 1;
                    }
                    return (C2344d0.f6035a >= 26 || !str2.equals("OMX.MTK.AUDIO.DECODER.RAW")) ? 0 : -1;
                }
            });
        }
        int i2 = C2344d0.f6035a;
        if (i2 < 21 && list.size() > 1) {
            String str2 = list.get(0).f4280a;
            if ("OMX.SEC.mp3.dec".equals(str2) || "OMX.SEC.MP3.Decoder".equals(str2) || "OMX.brcm.audio.mp3.decoder".equals(str2)) {
                m1697i(list, new g() { // from class: b.l.a.a.g1.b
                    @Override // p005b.p199l.p200a.p201a.p219g1.C2075h.g
                    /* renamed from: a */
                    public final int mo1652a(Object obj) {
                        Pattern pattern = C2075h.f4352a;
                        return ((C2072e) obj).f4280a.startsWith("OMX.google") ? 1 : 0;
                    }
                });
            }
        }
        if (i2 >= 30 || list.size() <= 1 || !"OMX.qti.audio.decoder.flac".equals(list.get(0).f4280a)) {
            return;
        }
        list.add(list.remove(0));
    }

    /* JADX WARN: Code restructure failed: missing block: B:108:0x01b0, code lost:
    
        if (r2.startsWith("t0") == false) goto L117;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0071, code lost:
    
        if (r0.startsWith("HM") == false) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x00e1, code lost:
    
        if ("SO-02E".equals(r2) == false) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x010f, code lost:
    
        if ("C1605".equals(r0) == false) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x0171, code lost:
    
        if ("SCV31".equals(r0) == false) goto L100;
     */
    /* JADX WARN: Removed duplicated region for block: B:121:0x01dd A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:123:0x01de  */
    @androidx.annotation.Nullable
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String m1690b(android.media.MediaCodecInfo r5, java.lang.String r6, boolean r7, java.lang.String r8) {
        /*
            Method dump skipped, instructions count: 574
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.C2075h.m1690b(android.media.MediaCodecInfo, java.lang.String, boolean, java.lang.String):java.lang.String");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Nullable
    /* renamed from: c */
    public static Pair<Integer, Integer> m1691c(Format format) {
        char c2;
        int i2;
        int parseInt;
        int parseInt2;
        int i3;
        int i4;
        String str = format.f9242i;
        if (str == null) {
            return null;
        }
        String[] split = str.split("\\.");
        if ("video/dolby-vision".equals(format.f9245l)) {
            if (split.length < 3) {
                return null;
            }
            Matcher matcher = f4352a.matcher(split[1]);
            if (!matcher.matches()) {
                return null;
            }
            Integer num = f4359h.get(matcher.group(1));
            if (num == null) {
                return null;
            }
            Integer num2 = f4360i.get(split[2]);
            if (num2 == null) {
                return null;
            }
            return new Pair<>(num, num2);
        }
        String str2 = split[0];
        str2.hashCode();
        switch (str2.hashCode()) {
            case 3004662:
                if (str2.equals("av01")) {
                    c2 = 0;
                    break;
                }
                c2 = 65535;
                break;
            case 3006243:
                if (str2.equals("avc1")) {
                    c2 = 1;
                    break;
                }
                c2 = 65535;
                break;
            case 3006244:
                if (str2.equals("avc2")) {
                    c2 = 2;
                    break;
                }
                c2 = 65535;
                break;
            case 3199032:
                if (str2.equals("hev1")) {
                    c2 = 3;
                    break;
                }
                c2 = 65535;
                break;
            case 3214780:
                if (str2.equals("hvc1")) {
                    c2 = 4;
                    break;
                }
                c2 = 65535;
                break;
            case 3356560:
                if (str2.equals("mp4a")) {
                    c2 = 5;
                    break;
                }
                c2 = 65535;
                break;
            case 3624515:
                if (str2.equals("vp09")) {
                    c2 = 6;
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
                ColorInfo colorInfo = format.f9257x;
                if (split.length < 4) {
                    return null;
                }
                try {
                    int parseInt3 = Integer.parseInt(split[1]);
                    int parseInt4 = Integer.parseInt(split[2].substring(0, 2));
                    int parseInt5 = Integer.parseInt(split[3]);
                    if (parseInt3 != 0) {
                        return null;
                    }
                    if (parseInt5 != 8 && parseInt5 != 10) {
                        return null;
                    }
                    r4 = parseInt5 != 8 ? (colorInfo == null || !(colorInfo.f9747g != null || (i2 = colorInfo.f9746f) == 7 || i2 == 6)) ? 2 : 4096 : 1;
                    int i5 = f4361j.get(parseInt4, -1);
                    if (i5 == -1) {
                        return null;
                    }
                    return new Pair<>(Integer.valueOf(r4), Integer.valueOf(i5));
                } catch (NumberFormatException unused) {
                    return null;
                }
            case 1:
            case 2:
                if (split.length < 2) {
                    return null;
                }
                try {
                    if (split[1].length() == 6) {
                        parseInt = Integer.parseInt(split[1].substring(0, 2), 16);
                        parseInt2 = Integer.parseInt(split[1].substring(4), 16);
                    } else {
                        if (split.length < 3) {
                            return null;
                        }
                        parseInt = Integer.parseInt(split[1]);
                        parseInt2 = Integer.parseInt(split[2]);
                    }
                    int i6 = f4354c.get(parseInt, -1);
                    if (i6 == -1 || (i3 = f4355d.get(parseInt2, -1)) == -1) {
                        return null;
                    }
                    return new Pair<>(Integer.valueOf(i6), Integer.valueOf(i3));
                } catch (NumberFormatException unused2) {
                    return null;
                }
            case 3:
            case 4:
                if (split.length < 4) {
                    return null;
                }
                Matcher matcher2 = f4352a.matcher(split[1]);
                if (!matcher2.matches()) {
                    return null;
                }
                String group = matcher2.group(1);
                if (!"1".equals(group)) {
                    if (!"2".equals(group)) {
                        return null;
                    }
                    r4 = 2;
                }
                Integer num3 = f4358g.get(split[3]);
                if (num3 == null) {
                    return null;
                }
                return new Pair<>(Integer.valueOf(r4), num3);
            case 5:
                if (split.length != 3) {
                    return null;
                }
                try {
                    if (!"audio/mp4a-latm".equals(C2357q.m2541d(Integer.parseInt(split[1], 16)))) {
                        return null;
                    }
                    int i7 = f4362k.get(Integer.parseInt(split[2]), -1);
                    if (i7 != -1) {
                        return new Pair<>(Integer.valueOf(i7), 0);
                    }
                    return null;
                } catch (NumberFormatException unused3) {
                    return null;
                }
            case 6:
                if (split.length < 3) {
                    return null;
                }
                try {
                    int parseInt6 = Integer.parseInt(split[1]);
                    int parseInt7 = Integer.parseInt(split[2]);
                    int i8 = f4356e.get(parseInt6, -1);
                    if (i8 == -1 || (i4 = f4357f.get(parseInt7, -1)) == -1) {
                        return null;
                    }
                    return new Pair<>(Integer.valueOf(i8), Integer.valueOf(i4));
                } catch (NumberFormatException unused4) {
                    return null;
                }
            default:
                return null;
        }
    }

    @Nullable
    /* renamed from: d */
    public static C2072e m1692d(String str, boolean z, boolean z2) {
        List<C2072e> m1693e = m1693e(str, z, z2);
        if (m1693e.isEmpty()) {
            return null;
        }
        return m1693e.get(0);
    }

    /* renamed from: e */
    public static synchronized List<C2072e> m1693e(String str, boolean z, boolean z2) {
        synchronized (C2075h.class) {
            b bVar = new b(str, z, z2);
            HashMap<b, List<C2072e>> hashMap = f4353b;
            List<C2072e> list = hashMap.get(bVar);
            if (list != null) {
                return list;
            }
            int i2 = C2344d0.f6035a;
            ArrayList<C2072e> m1694f = m1694f(bVar, i2 >= 21 ? new f(z, z2) : new e(null));
            if (z && m1694f.isEmpty() && 21 <= i2 && i2 <= 23) {
                m1694f = m1694f(bVar, new e(null));
                if (!m1694f.isEmpty()) {
                    String str2 = m1694f.get(0).f4280a;
                }
            }
            m1689a(str, m1694f);
            List<C2072e> unmodifiableList = Collections.unmodifiableList(m1694f);
            hashMap.put(bVar, unmodifiableList);
            return unmodifiableList;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:33:0x00b1, code lost:
    
        if ("Nexus 10".equals(r10) == false) goto L46;
     */
    /* renamed from: f */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList<p005b.p199l.p200a.p201a.p219g1.C2072e> m1694f(p005b.p199l.p200a.p201a.p219g1.C2075h.b r24, p005b.p199l.p200a.p201a.p219g1.C2075h.d r25) {
        /*
            Method dump skipped, instructions count: 319
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.C2075h.m1694f(b.l.a.a.g1.h$b, b.l.a.a.g1.h$d):java.util.ArrayList");
    }

    /* renamed from: g */
    public static boolean m1695g(MediaCodecInfo mediaCodecInfo) {
        if (C2344d0.f6035a >= 29) {
            return mediaCodecInfo.isSoftwareOnly();
        }
        String m2320L = C2344d0.m2320L(mediaCodecInfo.getName());
        if (m2320L.startsWith("arc.")) {
            return false;
        }
        return m2320L.startsWith("omx.google.") || m2320L.startsWith("omx.ffmpeg.") || (m2320L.startsWith("omx.sec.") && m2320L.contains(".sw.")) || m2320L.equals("omx.qcom.video.decoder.hevcswvdec") || m2320L.startsWith("c2.android.") || m2320L.startsWith("c2.google.") || !(m2320L.startsWith("omx.") || m2320L.startsWith("c2."));
    }

    /* renamed from: h */
    public static int m1696h() {
        int i2;
        if (f4363l == -1) {
            int i3 = 0;
            C2072e m1692d = m1692d("video/avc", false, false);
            if (m1692d != null) {
                MediaCodecInfo.CodecProfileLevel[] m1656c = m1692d.m1656c();
                int length = m1656c.length;
                int i4 = 0;
                while (i3 < length) {
                    int i5 = m1656c[i3].level;
                    if (i5 != 1 && i5 != 2) {
                        switch (i5) {
                            case 8:
                            case 16:
                            case 32:
                                i2 = 101376;
                                break;
                            case 64:
                                i2 = 202752;
                                break;
                            case 128:
                            case 256:
                                i2 = 414720;
                                break;
                            case 512:
                                i2 = 921600;
                                break;
                            case 1024:
                                i2 = 1310720;
                                break;
                            case 2048:
                            case 4096:
                                i2 = 2097152;
                                break;
                            case 8192:
                                i2 = 2228224;
                                break;
                            case 16384:
                                i2 = 5652480;
                                break;
                            case 32768:
                            case 65536:
                                i2 = 9437184;
                                break;
                            default:
                                i2 = -1;
                                break;
                        }
                    } else {
                        i2 = 25344;
                    }
                    i4 = Math.max(i2, i4);
                    i3++;
                }
                i3 = Math.max(i4, C2344d0.f6035a >= 21 ? 345600 : 172800);
            }
            f4363l = i3;
        }
        return f4363l;
    }

    /* renamed from: i */
    public static <T> void m1697i(List<T> list, final g<T> gVar) {
        Collections.sort(list, new Comparator() { // from class: b.l.a.a.g1.d
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                C2075h.g gVar2 = C2075h.g.this;
                return gVar2.mo1652a(obj2) - gVar2.mo1652a(obj);
            }
        });
    }
}
