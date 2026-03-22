package p005b.p199l.p200a.p201a.p250p1;

import android.text.TextUtils;
import androidx.annotation.Nullable;
import com.alibaba.fastjson.asm.Opcodes;
import com.luck.picture.lib.config.PictureMimeType;
import java.util.ArrayList;
import java.util.Objects;

/* renamed from: b.l.a.a.p1.q */
/* loaded from: classes.dex */
public final class C2357q {

    /* renamed from: a */
    public static final ArrayList<a> f6108a = new ArrayList<>();

    /* renamed from: b.l.a.a.p1.q$a */
    public static final class a {
    }

    @Nullable
    /* renamed from: a */
    public static String m2538a(@Nullable String str) {
        if (str == null) {
            return null;
        }
        for (String str2 : C2344d0.m2318J(str)) {
            String m2540c = m2540c(str2);
            if (m2540c != null && m2545h(m2540c)) {
                return m2540c;
            }
        }
        return null;
    }

    /* renamed from: b */
    public static int m2539b(String str) {
        str.hashCode();
        switch (str) {
            case "audio/eac3-joc":
                return 18;
            case "audio/vnd.dts":
                return 7;
            case "audio/ac3":
                return 5;
            case "audio/ac4":
                return 17;
            case "audio/eac3":
                return 6;
            case "audio/mpeg":
                return 9;
            case "audio/vnd.dts.hd":
                return 8;
            case "audio/true-hd":
                return 14;
            default:
                return 0;
        }
    }

    @Nullable
    /* renamed from: c */
    public static String m2540c(@Nullable String str) {
        String str2 = null;
        if (str == null) {
            return null;
        }
        String m2320L = C2344d0.m2320L(str.trim());
        if (m2320L.startsWith("avc1") || m2320L.startsWith("avc3")) {
            return "video/avc";
        }
        if (m2320L.startsWith("hev1") || m2320L.startsWith("hvc1")) {
            return "video/hevc";
        }
        if (m2320L.startsWith("dvav") || m2320L.startsWith("dva1") || m2320L.startsWith("dvhe") || m2320L.startsWith("dvh1")) {
            return "video/dolby-vision";
        }
        if (m2320L.startsWith("av01")) {
            return "video/av01";
        }
        if (m2320L.startsWith("vp9") || m2320L.startsWith("vp09")) {
            return "video/x-vnd.on2.vp9";
        }
        if (m2320L.startsWith("vp8") || m2320L.startsWith("vp08")) {
            return "video/x-vnd.on2.vp8";
        }
        if (m2320L.startsWith("mp4a")) {
            if (m2320L.startsWith("mp4a.")) {
                String substring = m2320L.substring(5);
                if (substring.length() >= 2) {
                    try {
                        str2 = m2541d(Integer.parseInt(C2344d0.m2322N(substring.substring(0, 2)), 16));
                    } catch (NumberFormatException unused) {
                    }
                }
            }
            return str2 == null ? "audio/mp4a-latm" : str2;
        }
        if (m2320L.startsWith("ac-3") || m2320L.startsWith("dac3")) {
            return "audio/ac3";
        }
        if (m2320L.startsWith("ec-3") || m2320L.startsWith("dec3")) {
            return "audio/eac3";
        }
        if (m2320L.startsWith("ec+3")) {
            return "audio/eac3-joc";
        }
        if (m2320L.startsWith("ac-4") || m2320L.startsWith("dac4")) {
            return "audio/ac4";
        }
        if (m2320L.startsWith("dtsc") || m2320L.startsWith("dtse")) {
            return "audio/vnd.dts";
        }
        if (m2320L.startsWith("dtsh") || m2320L.startsWith("dtsl")) {
            return "audio/vnd.dts.hd";
        }
        if (m2320L.startsWith("opus")) {
            return "audio/opus";
        }
        if (m2320L.startsWith("vorbis")) {
            return "audio/vorbis";
        }
        if (m2320L.startsWith("flac")) {
            return "audio/flac";
        }
        int size = f6108a.size();
        for (int i2 = 0; i2 < size; i2++) {
            Objects.requireNonNull(f6108a.get(i2));
            if (m2320L.startsWith(null)) {
                break;
            }
        }
        return null;
    }

    @Nullable
    /* renamed from: d */
    public static String m2541d(int i2) {
        if (i2 == 32) {
            return "video/mp4v-es";
        }
        if (i2 == 33) {
            return "video/avc";
        }
        if (i2 == 35) {
            return "video/hevc";
        }
        if (i2 == 64) {
            return "audio/mp4a-latm";
        }
        if (i2 == 163) {
            return "video/wvc1";
        }
        if (i2 == 177) {
            return "video/x-vnd.on2.vp9";
        }
        if (i2 == 165) {
            return "audio/ac3";
        }
        if (i2 == 166) {
            return "audio/eac3";
        }
        switch (i2) {
            case 96:
            case 97:
            case 98:
            case 99:
            case 100:
            case 101:
                return "video/mpeg2";
            case 102:
            case 103:
            case 104:
                return "audio/mp4a-latm";
            case 105:
            case 107:
                return PictureMimeType.MIME_TYPE_AUDIO;
            case 106:
                return "video/mpeg";
            default:
                switch (i2) {
                    case Opcodes.RET /* 169 */:
                    case 172:
                        return "audio/vnd.dts";
                    case 170:
                    case 171:
                        return "audio/vnd.dts.hd";
                    case 173:
                        return "audio/opus";
                    case 174:
                        return "audio/ac4";
                    default:
                        return null;
                }
        }
    }

    @Nullable
    /* renamed from: e */
    public static String m2542e(@Nullable String str) {
        int indexOf;
        if (str == null || (indexOf = str.indexOf(47)) == -1) {
            return null;
        }
        return str.substring(0, indexOf);
    }

    /* renamed from: f */
    public static int m2543f(@Nullable String str) {
        if (TextUtils.isEmpty(str)) {
            return -1;
        }
        if (m2545h(str)) {
            return 1;
        }
        if (m2547j(str)) {
            return 2;
        }
        if (m2546i(str) || "application/cea-608".equals(str) || "application/cea-708".equals(str) || "application/x-mp4-cea-608".equals(str) || "application/x-subrip".equals(str) || "application/ttml+xml".equals(str) || "application/x-quicktime-tx3g".equals(str) || "application/x-mp4-vtt".equals(str) || "application/x-rawcc".equals(str) || "application/vobsub".equals(str) || "application/pgs".equals(str) || "application/dvbsubs".equals(str)) {
            return 3;
        }
        if ("application/id3".equals(str) || "application/x-emsg".equals(str) || "application/x-scte35".equals(str)) {
            return 4;
        }
        if ("application/x-camera-motion".equals(str)) {
            return 5;
        }
        int size = f6108a.size();
        for (int i2 = 0; i2 < size; i2++) {
            Objects.requireNonNull(f6108a.get(i2));
            if (str.equals(null)) {
                return 0;
            }
        }
        return -1;
    }

    @Nullable
    /* renamed from: g */
    public static String m2544g(@Nullable String str) {
        if (str == null) {
            return null;
        }
        for (String str2 : C2344d0.m2318J(str)) {
            String m2540c = m2540c(str2);
            if (m2540c != null && m2547j(m2540c)) {
                return m2540c;
            }
        }
        return null;
    }

    /* renamed from: h */
    public static boolean m2545h(@Nullable String str) {
        return "audio".equals(m2542e(str));
    }

    /* renamed from: i */
    public static boolean m2546i(@Nullable String str) {
        return "text".equals(m2542e(str));
    }

    /* renamed from: j */
    public static boolean m2547j(@Nullable String str) {
        return "video".equals(m2542e(str));
    }
}
