package p005b.p199l.p200a.p201a.p250p1;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import com.alibaba.fastjson.asm.Label;
import com.alibaba.fastjson.asm.Opcodes;
import com.google.android.material.behavior.HideBottomViewOnScrollBehavior;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.Formatter;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.C2400v0;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.a.a.p1.d0 */
/* loaded from: classes.dex */
public final class C2344d0 {

    /* renamed from: a */
    public static final int f6035a;

    /* renamed from: b */
    public static final String f6036b;

    /* renamed from: c */
    public static final String f6037c;

    /* renamed from: d */
    public static final String f6038d;

    /* renamed from: e */
    public static final String f6039e;

    /* renamed from: f */
    public static final byte[] f6040f;

    /* renamed from: g */
    public static final Pattern f6041g;

    /* renamed from: h */
    public static final Pattern f6042h;

    /* renamed from: i */
    public static final Pattern f6043i;

    /* renamed from: j */
    @Nullable
    public static HashMap<String, String> f6044j;

    /* renamed from: k */
    public static final String[] f6045k;

    /* renamed from: l */
    public static final String[] f6046l;

    /* renamed from: m */
    public static final int[] f6047m;

    /* renamed from: n */
    public static final int[] f6048n;

    static {
        int i2 = Build.VERSION.SDK_INT;
        f6035a = i2;
        String str = Build.DEVICE;
        f6036b = str;
        String str2 = Build.MANUFACTURER;
        f6037c = str2;
        String str3 = Build.MODEL;
        f6038d = str3;
        f6039e = str + ", " + str3 + ", " + str2 + ", " + i2;
        f6040f = new byte[0];
        f6041g = Pattern.compile("(\\d\\d\\d\\d)\\-(\\d\\d)\\-(\\d\\d)[Tt](\\d\\d):(\\d\\d):(\\d\\d)([\\.,](\\d+))?([Zz]|((\\+|\\-)(\\d?\\d):?(\\d\\d)))?");
        f6042h = Pattern.compile("^(-)?P(([0-9]*)Y)?(([0-9]*)M)?(([0-9]*)D)?(T(([0-9]*)H)?(([0-9]*)M)?(([0-9.]*)S)?)?$");
        f6043i = Pattern.compile("%([A-Fa-f0-9]{2})");
        f6045k = new String[]{"alb", "sq", "arm", "hy", "baq", "eu", "bur", "my", "tib", "bo", "chi", "zh", "cze", "cs", "dut", "nl", "ger", "de", "gre", "el", "fre", "fr", "geo", "ka", "ice", "is", "mac", "mk", "mao", "mi", "may", "ms", "per", "fa", "rum", "ro", "scc", "hbs-srp", "slo", "sk", "wel", "cy", "id", "ms-ind", "iw", "he", "heb", "he", "ji", "yi", "in", "ms-ind", "ind", "ms-ind", "nb", "no-nob", "nob", "no-nob", "nn", "no-nno", "nno", "no-nno", "tw", "ak-twi", "twi", "ak-twi", "bs", "hbs-bos", "bos", "hbs-bos", "hr", "hbs-hrv", "hrv", "hbs-hrv", "sr", "hbs-srp", "srp", "hbs-srp", "cmn", "zh-cmn", "hak", "zh-hak", "nan", "zh-nan", "hsn", "zh-hsn"};
        f6046l = new String[]{"i-lux", "lb", "i-hak", "zh-hak", "i-navajo", "nv", "no-bok", "no-nob", "no-nyn", "no-nno", "zh-guoyu", "zh-cmn", "zh-hakka", "zh-hak", "zh-min-nan", "zh-nan", "zh-xiang", "zh-hsn"};
        f6047m = new int[]{0, 79764919, 159529838, 222504665, 319059676, 398814059, 445009330, 507990021, 638119352, 583659535, 797628118, 726387553, 890018660, 835552979, 1015980042, 944750013, 1276238704, 1221641927, 1167319070, 1095957929, 1595256236, 1540665371, 1452775106, 1381403509, 1780037320, 1859660671, 1671105958, 1733955601, 2031960084, 2111593891, 1889500026, 1952343757, -1742489888, -1662866601, -1851683442, -1788833735, -1960329156, -1880695413, -2103051438, -2040207643, -1104454824, -1159051537, -1213636554, -1284997759, -1389417084, -1444007885, -1532160278, -1603531939, -734892656, -789352409, -575645954, -646886583, -952755380, -1007220997, -827056094, -898286187, -231047128, -151282273, -71779514, -8804623, -515967244, -436212925, -390279782, -327299027, 881225847, 809987520, 1023691545, 969234094, 662832811, 591600412, 771767749, 717299826, 311336399, 374308984, 453813921, 533576470, 25881363, 88864420, 134795389, 214552010, 2023205639, 2086057648, 1897238633, 1976864222, 1804852699, 1867694188, 1645340341, 1724971778, 1587496639, 1516133128, 1461550545, 1406951526, 1302016099, 1230646740, 1142491917, 1087903418, -1398421865, -1469785312, -1524105735, -1578704818, -1079922613, -1151291908, -1239184603, -1293773166, -1968362705, -1905510760, -2094067647, -2014441994, -1716953613, -1654112188, -1876203875, -1796572374, -525066777, -462094256, -382327159, -302564546, -206542021, -143559028, -97365931, -17609246, -960696225, -1031934488, -817968335, -872425850, -709327229, -780559564, -600130067, -654598054, 1762451694, 1842216281, 1619975040, 1682949687, 2047383090, 2127137669, 1938468188, 2001449195, 1325665622, 1271206113, 1183200824, 1111960463, 1543535498, 1489069629, 1434599652, 1363369299, 622672798, 568075817, 748617968, 677256519, 907627842, 853037301, 1067152940, 995781531, 51762726, 131386257, 177728840, 240578815, 269590778, 349224269, 429104020, 491947555, -248556018, -168932423, -122852000, -60002089, -500490030, -420856475, -341238852, -278395381, -685261898, -739858943, -559578920, -630940305, -1004286614, -1058877219, -845023740, -916395085, -1119974018, -1174433591, -1262701040, -1333941337, -1371866206, -1426332139, -1481064244, -1552294533, -1690935098, -1611170447, -1833673816, -1770699233, -2009983462, -1930228819, -2119160460, -2056179517, 1569362073, 1498123566, 1409854455, 1355396672, 1317987909, 1246755826, 1192025387, 1137557660, 2072149281, 2135122070, 1912620623, 1992383480, 1753615357, 1816598090, 1627664531, 1707420964, 295390185, 358241886, 404320391, 483945776, 43990325, 106832002, 186451547, 266083308, 932423249, 861060070, 1041341759, 986742920, 613929101, 542559546, 756411363, 701822548, -978770311, -1050133554, -869589737, -924188512, -693284699, -764654318, -550540341, -605129092, -475935807, -413084042, -366743377, -287118056, -257573603, -194731862, -114850189, -35218492, -1984365303, -1921392450, -2143631769, -2063868976, -1698919467, -1635936670, -1824608069, -1744851700, -1347415887, -1418654458, -1506661409, -1561119128, -1129027987, -1200260134, -1254728445, -1309196108};
        f6048n = new int[]{0, 7, 14, 9, 28, 27, 18, 21, 56, 63, 54, 49, 36, 35, 42, 45, 112, 119, 126, 121, 108, 107, 98, 101, 72, 79, 70, 65, 84, 83, 90, 93, 224, 231, 238, 233, 252, 251, 242, 245, 216, 223, 214, 209, 196, 195, 202, 205, IjkMediaMeta.FF_PROFILE_H264_HIGH_444, Opcodes.DCMPL, Opcodes.IFLE, Opcodes.IFEQ, 140, 139, 130, 133, 168, HideBottomViewOnScrollBehavior.EXIT_ANIMATION_DURATION, 166, Opcodes.IF_ICMPLT, 180, 179, 186, 189, Opcodes.IFNONNULL, Opcodes.CHECKCAST, 201, 206, 219, 220, 213, 210, 255, 248, 241, 246, 227, 228, 237, 234, Opcodes.INVOKESPECIAL, Opcodes.ARETURN, Opcodes.INVOKEINTERFACE, 190, 171, 172, Opcodes.IF_ACMPEQ, Opcodes.IF_ICMPGE, 143, 136, 129, 134, 147, Opcodes.LCMP, 157, Opcodes.IFNE, 39, 32, 41, 46, 59, 60, 53, 50, 31, 24, 17, 22, 3, 4, 13, 10, 87, 80, 89, 94, 75, 76, 69, 66, 111, 104, 97, 102, 115, 116, 125, 122, 137, 142, 135, 128, Opcodes.FCMPL, 146, 155, 156, Opcodes.RETURN, Opcodes.INVOKEVIRTUAL, 191, Opcodes.INVOKESTATIC, 173, 170, Opcodes.IF_ICMPGT, 164, 249, 254, 247, 240, 229, 226, 235, 236, Opcodes.INSTANCEOF, Opcodes.IFNULL, 207, 200, 221, 218, 211, 212, 105, 110, 103, 96, 117, 114, 123, 124, 81, 86, 95, 88, 77, 74, 67, 68, 25, 30, 23, 16, 5, 2, 11, 12, 33, 38, 47, 40, 61, 58, 51, 52, 78, 73, 64, 71, 82, 85, 92, 91, 118, 113, 120, 127, 106, 109, 100, 99, 62, 57, 48, 55, 34, 37, 44, 43, 6, 1, 8, 15, 26, 29, 20, 19, 174, Opcodes.RET, Opcodes.IF_ICMPNE, Opcodes.GOTO, Opcodes.GETSTATIC, Opcodes.PUTFIELD, 188, Opcodes.NEW, 150, 145, 152, Opcodes.IF_ICMPEQ, 138, 141, 132, 131, 222, 217, 208, 215, 194, 197, 204, 203, 230, HideBottomViewOnScrollBehavior.ENTER_ANIMATION_DURATION, 232, 239, 250, 253, IjkMediaMeta.FF_PROFILE_H264_HIGH_444_PREDICTIVE, 243};
    }

    /* renamed from: A */
    public static <T> T[] m2309A(T[] tArr, int i2) {
        C4195m.m4765F(i2 <= tArr.length);
        return (T[]) Arrays.copyOf(tArr, i2);
    }

    /* renamed from: B */
    public static <T> T[] m2310B(T[] tArr, int i2, int i3) {
        C4195m.m4765F(i2 >= 0);
        C4195m.m4765F(i3 <= tArr.length);
        return (T[]) Arrays.copyOfRange(tArr, i2, i3);
    }

    /* renamed from: C */
    public static long m2311C(String str) {
        Matcher matcher = f6041g.matcher(str);
        if (!matcher.matches()) {
            throw new C2205l0(C1499a.m637w("Invalid date/time format: ", str));
        }
        int i2 = 0;
        if (matcher.group(9) != null && !matcher.group(9).equalsIgnoreCase("Z")) {
            i2 = Integer.parseInt(matcher.group(13)) + (Integer.parseInt(matcher.group(12)) * 60);
            if ("-".equals(matcher.group(11))) {
                i2 *= -1;
            }
        }
        GregorianCalendar gregorianCalendar = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        gregorianCalendar.clear();
        gregorianCalendar.set(Integer.parseInt(matcher.group(1)), Integer.parseInt(matcher.group(2)) - 1, Integer.parseInt(matcher.group(3)), Integer.parseInt(matcher.group(4)), Integer.parseInt(matcher.group(5)), Integer.parseInt(matcher.group(6)));
        if (!TextUtils.isEmpty(matcher.group(8))) {
            StringBuilder m586H = C1499a.m586H("0.");
            m586H.append(matcher.group(8));
            gregorianCalendar.set(14, new BigDecimal(m586H.toString()).movePointRight(3).intValue());
        }
        long timeInMillis = gregorianCalendar.getTimeInMillis();
        return i2 != 0 ? timeInMillis - (i2 * 60000) : timeInMillis;
    }

    /* renamed from: D */
    public static <T> void m2312D(List<T> list, int i2, int i3) {
        if (i2 < 0 || i3 > list.size() || i2 > i3) {
            throw new IllegalArgumentException();
        }
        if (i2 != i3) {
            list.subList(i2, i3).clear();
        }
    }

    /* renamed from: E */
    public static long m2313E(long j2, C2400v0 c2400v0, long j3, long j4) {
        if (C2400v0.f6332a.equals(c2400v0)) {
            return j2;
        }
        long j5 = c2400v0.f6334c;
        long j6 = j2 - j5;
        long j7 = ((j5 ^ j2) & (j2 ^ j6)) >= 0 ? j6 : Long.MIN_VALUE;
        long j8 = c2400v0.f6335d;
        long j9 = j2 + j8;
        long j10 = ((j8 ^ j9) & (j2 ^ j9)) >= 0 ? j9 : Long.MAX_VALUE;
        boolean z = false;
        boolean z2 = j7 <= j3 && j3 <= j10;
        if (j7 <= j4 && j4 <= j10) {
            z = true;
        }
        return (z2 && z) ? Math.abs(j3 - j2) <= Math.abs(j4 - j2) ? j3 : j4 : z2 ? j3 : z ? j4 : j7;
    }

    /* renamed from: F */
    public static long m2314F(long j2, long j3, long j4) {
        if (j4 >= j3 && j4 % j3 == 0) {
            return j2 / (j4 / j3);
        }
        if (j4 < j3 && j3 % j4 == 0) {
            return (j3 / j4) * j2;
        }
        return (long) (j2 * (j3 / j4));
    }

    /* renamed from: G */
    public static void m2315G(long[] jArr, long j2, long j3) {
        int i2 = 0;
        if (j3 >= j2 && j3 % j2 == 0) {
            long j4 = j3 / j2;
            while (i2 < jArr.length) {
                jArr[i2] = jArr[i2] / j4;
                i2++;
            }
            return;
        }
        if (j3 >= j2 || j2 % j3 != 0) {
            double d2 = j2 / j3;
            while (i2 < jArr.length) {
                jArr[i2] = (long) (jArr[i2] * d2);
                i2++;
            }
            return;
        }
        long j5 = j2 / j3;
        while (i2 < jArr.length) {
            jArr[i2] = jArr[i2] * j5;
            i2++;
        }
    }

    /* renamed from: H */
    public static String[] m2316H(String str, String str2) {
        return str.split(str2, -1);
    }

    /* renamed from: I */
    public static String[] m2317I(String str, String str2) {
        return str.split(str2, 2);
    }

    /* renamed from: J */
    public static String[] m2318J(@Nullable String str) {
        return TextUtils.isEmpty(str) ? new String[0] : m2316H(str.trim(), "(\\s*,\\s*)");
    }

    /* renamed from: K */
    public static int[] m2319K(List<Integer> list) {
        int size = list.size();
        int[] iArr = new int[size];
        for (int i2 = 0; i2 < size; i2++) {
            iArr[i2] = list.get(i2).intValue();
        }
        return iArr;
    }

    /* renamed from: L */
    public static String m2320L(String str) {
        return str == null ? str : str.toLowerCase(Locale.US);
    }

    /* renamed from: M */
    public static long m2321M(int i2) {
        return i2 & 4294967295L;
    }

    /* renamed from: N */
    public static String m2322N(String str) {
        return str == null ? str : str.toUpperCase(Locale.US);
    }

    /* renamed from: a */
    public static boolean m2323a(@Nullable Object obj, @Nullable Object obj2) {
        return obj == null ? obj2 == null : obj.equals(obj2);
    }

    /* renamed from: b */
    public static int m2324b(long[] jArr, long j2, boolean z, boolean z2) {
        int i2;
        int binarySearch = Arrays.binarySearch(jArr, j2);
        if (binarySearch < 0) {
            i2 = ~binarySearch;
        } else {
            do {
                binarySearch++;
                if (binarySearch >= jArr.length) {
                    break;
                }
            } while (jArr[binarySearch] == j2);
            i2 = z ? binarySearch - 1 : binarySearch;
        }
        return z2 ? Math.min(jArr.length - 1, i2) : i2;
    }

    /* renamed from: c */
    public static <T extends Comparable<? super T>> int m2325c(List<? extends Comparable<? super T>> list, T t, boolean z, boolean z2) {
        int i2;
        int binarySearch = Collections.binarySearch(list, t);
        if (binarySearch < 0) {
            i2 = -(binarySearch + 2);
        } else {
            do {
                binarySearch--;
                if (binarySearch < 0) {
                    break;
                }
            } while (list.get(binarySearch).compareTo(t) == 0);
            i2 = z ? binarySearch + 1 : binarySearch;
        }
        return z2 ? Math.max(0, i2) : i2;
    }

    /* renamed from: d */
    public static int m2326d(long[] jArr, long j2, boolean z, boolean z2) {
        int i2;
        int binarySearch = Arrays.binarySearch(jArr, j2);
        if (binarySearch < 0) {
            i2 = -(binarySearch + 2);
        } else {
            do {
                binarySearch--;
                if (binarySearch < 0) {
                    break;
                }
            } while (jArr[binarySearch] == j2);
            i2 = z ? binarySearch + 1 : binarySearch;
        }
        return z2 ? Math.max(0, i2) : i2;
    }

    /* renamed from: e */
    public static int m2327e(int i2, int i3) {
        return ((i2 + i3) - 1) / i3;
    }

    /* renamed from: f */
    public static float m2328f(float f2, float f3, float f4) {
        return Math.max(f3, Math.min(f2, f4));
    }

    /* renamed from: g */
    public static int m2329g(int i2, int i3, int i4) {
        return Math.max(i3, Math.min(i2, i4));
    }

    /* renamed from: h */
    public static long m2330h(long j2, long j3, long j4) {
        return Math.max(j3, Math.min(j2, j4));
    }

    /* renamed from: i */
    public static boolean m2331i(Object[] objArr, @Nullable Object obj) {
        for (Object obj2 : objArr) {
            if (m2323a(obj2, obj)) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: j */
    public static String m2332j(String str, Object... objArr) {
        return String.format(Locale.US, str, objArr);
    }

    /* renamed from: k */
    public static String m2333k(byte[] bArr, int i2, int i3) {
        return new String(bArr, i2, i3, Charset.forName("UTF-8"));
    }

    @Nullable
    /* renamed from: l */
    public static String m2334l(@Nullable String str, int i2) {
        String[] m2318J = m2318J(str);
        if (m2318J.length == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (String str2 : m2318J) {
            if (i2 == C2357q.m2543f(C2357q.m2540c(str2))) {
                if (sb.length() > 0) {
                    sb.append(ChineseToPinyinResource.Field.COMMA);
                }
                sb.append(str2);
            }
        }
        if (sb.length() > 0) {
            return sb.toString();
        }
        return null;
    }

    /* renamed from: m */
    public static int m2335m(Context context) {
        ConnectivityManager connectivityManager;
        int i2 = 0;
        if (context == null || (connectivityManager = (ConnectivityManager) context.getSystemService("connectivity")) == null) {
            return 0;
        }
        try {
            NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
            i2 = 1;
            if (activeNetworkInfo != null && activeNetworkInfo.isConnected()) {
                int type = activeNetworkInfo.getType();
                if (type != 0) {
                    if (type == 1) {
                        return 2;
                    }
                    if (type != 4 && type != 5) {
                        if (type != 6) {
                            return type != 9 ? 8 : 7;
                        }
                        return 5;
                    }
                }
                switch (activeNetworkInfo.getSubtype()) {
                }
                return 0;
            }
        } catch (SecurityException unused) {
        }
        return i2;
    }

    /* renamed from: n */
    public static int m2336n(int i2) {
        if (i2 == 8) {
            return 3;
        }
        if (i2 != 16) {
            return i2 != 24 ? i2 != 32 ? 0 : 805306368 : Label.FORWARD_REFERENCE_TYPE_WIDE;
        }
        return 2;
    }

    /* renamed from: o */
    public static int m2337o(int i2, int i3) {
        if (i2 != 2) {
            if (i2 == 3) {
                return i3;
            }
            if (i2 != 4) {
                if (i2 != 268435456) {
                    if (i2 == 536870912) {
                        return i3 * 3;
                    }
                    if (i2 != 805306368) {
                        throw new IllegalArgumentException();
                    }
                }
            }
            return i3 * 4;
        }
        return i3 * 2;
    }

    /* renamed from: p */
    public static long m2338p(long j2, float f2) {
        return f2 == 1.0f ? j2 : Math.round(j2 / f2);
    }

    /* renamed from: q */
    public static int m2339q(int i2) {
        if (i2 == 13) {
            return 1;
        }
        switch (i2) {
            case 2:
                return 0;
            case 3:
                return 8;
            case 4:
                return 4;
            case 5:
            case 7:
            case 8:
            case 9:
            case 10:
                return 5;
            case 6:
                return 2;
            default:
                return 3;
        }
    }

    /* renamed from: r */
    public static String m2340r(StringBuilder sb, Formatter formatter, long j2) {
        if (j2 == -9223372036854775807L) {
            j2 = 0;
        }
        long j3 = (j2 + 500) / 1000;
        long j4 = j3 % 60;
        long j5 = (j3 / 60) % 60;
        long j6 = j3 / 3600;
        sb.setLength(0);
        return j6 > 0 ? formatter.format("%d:%02d:%02d", Long.valueOf(j6), Long.valueOf(j5), Long.valueOf(j4)).toString() : formatter.format("%02d:%02d", Long.valueOf(j5), Long.valueOf(j4)).toString();
    }

    /* renamed from: s */
    public static String m2341s(Context context, String str) {
        String str2;
        try {
            str2 = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
        } catch (PackageManager.NameNotFoundException unused) {
            str2 = "?";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append("/");
        sb.append(str2);
        sb.append(" (Linux;Android ");
        return C1499a.m583E(sb, Build.VERSION.RELEASE, ") ", "ExoPlayerLib/2.11.3");
    }

    /* renamed from: t */
    public static byte[] m2342t(String str) {
        return str.getBytes(Charset.forName("UTF-8"));
    }

    /* renamed from: u */
    public static int m2343u(String str) {
        String m2320L = m2320L(str);
        if (m2320L.endsWith(".mpd")) {
            return 0;
        }
        if (m2320L.endsWith(".m3u8")) {
            return 2;
        }
        return m2320L.matches(".*\\.ism(l)?(/manifest(\\(.+\\))?)?") ? 1 : 3;
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x005f, code lost:
    
        return false;
     */
    /* renamed from: v */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean m2344v(p005b.p199l.p200a.p201a.p250p1.C2360t r4, p005b.p199l.p200a.p201a.p250p1.C2360t r5, @androidx.annotation.Nullable java.util.zip.Inflater r6) {
        /*
            int r0 = r4.m2569a()
            r1 = 0
            if (r0 > 0) goto L8
            return r1
        L8:
            byte[] r0 = r5.f6133a
            int r2 = r0.length
            int r3 = r4.m2569a()
            if (r2 >= r3) goto L19
            int r0 = r4.m2569a()
            int r0 = r0 * 2
            byte[] r0 = new byte[r0]
        L19:
            if (r6 != 0) goto L20
            java.util.zip.Inflater r6 = new java.util.zip.Inflater
            r6.<init>()
        L20:
            byte[] r2 = r4.f6133a
            int r3 = r4.f6134b
            int r4 = r4.m2569a()
            r6.setInput(r2, r3, r4)
            r4 = 0
        L2c:
            int r2 = r0.length     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            int r2 = r2 - r4
            int r2 = r6.inflate(r0, r4, r2)     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            int r4 = r4 + r2
            boolean r2 = r6.finished()     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            if (r2 == 0) goto L44
            r5.f6133a = r0     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            r5.f6135c = r4     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            r5.f6134b = r1     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            r4 = 1
            r6.reset()
            return r4
        L44:
            boolean r2 = r6.needsDictionary()     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            if (r2 != 0) goto L5c
            boolean r2 = r6.needsInput()     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            if (r2 == 0) goto L51
            goto L5c
        L51:
            int r2 = r0.length     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            if (r4 != r2) goto L2c
            int r2 = r0.length     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            int r2 = r2 * 2
            byte[] r0 = java.util.Arrays.copyOf(r0, r2)     // Catch: java.lang.Throwable -> L60 java.util.zip.DataFormatException -> L65
            goto L2c
        L5c:
            r6.reset()
            return r1
        L60:
            r4 = move-exception
            r6.reset()
            throw r4
        L65:
            r6.reset()
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p250p1.C2344d0.m2344v(b.l.a.a.p1.t, b.l.a.a.p1.t, java.util.zip.Inflater):boolean");
    }

    /* renamed from: w */
    public static boolean m2345w(int i2) {
        return i2 == 536870912 || i2 == 805306368;
    }

    /* renamed from: x */
    public static boolean m2346x(int i2) {
        return i2 == 3 || i2 == 2 || i2 == 268435456 || i2 == 536870912 || i2 == 805306368 || i2 == 4;
    }

    /* renamed from: y */
    public static boolean m2347y(int i2) {
        return i2 == 10 || i2 == 13;
    }

    /* renamed from: z */
    public static String m2348z(String str) {
        if (str == null) {
            return null;
        }
        String replace = str.replace('_', '-');
        if (!replace.isEmpty() && !"und".equals(replace)) {
            str = replace;
        }
        String m2320L = m2320L(str);
        int i2 = 0;
        String str2 = m2317I(m2320L, "-")[0];
        if (f6044j == null) {
            String[] iSOLanguages = Locale.getISOLanguages();
            HashMap<String, String> hashMap = new HashMap<>(iSOLanguages.length + f6045k.length);
            for (String str3 : iSOLanguages) {
                try {
                    String iSO3Language = new Locale(str3).getISO3Language();
                    if (!TextUtils.isEmpty(iSO3Language)) {
                        hashMap.put(iSO3Language, str3);
                    }
                } catch (MissingResourceException unused) {
                }
            }
            int i3 = 0;
            while (true) {
                String[] strArr = f6045k;
                if (i3 >= strArr.length) {
                    break;
                }
                hashMap.put(strArr[i3], strArr[i3 + 1]);
                i3 += 2;
            }
            f6044j = hashMap;
        }
        String str4 = f6044j.get(str2);
        if (str4 != null) {
            StringBuilder m586H = C1499a.m586H(str4);
            m586H.append(m2320L.substring(str2.length()));
            m2320L = m586H.toString();
            str2 = str4;
        }
        if (!"no".equals(str2) && !"i".equals(str2) && !"zh".equals(str2)) {
            return m2320L;
        }
        while (true) {
            String[] strArr2 = f6046l;
            if (i2 >= strArr2.length) {
                return m2320L;
            }
            if (m2320L.startsWith(strArr2[i2])) {
                return strArr2[i2 + 1] + m2320L.substring(strArr2[i2].length());
            }
            i2 += 2;
        }
    }
}
