package p005b.p199l.p200a.p201a.p227k1.p232m0.p233s;

import android.net.Uri;
import android.text.TextUtils;
import android.util.Base64;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.hls.HlsTrackMetadataEntry;
import java.io.BufferedReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Queue;
import java.util.TreeMap;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.checkerframework.checker.nullness.qual.EnsuresNonNullIf;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2179d;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2180e;
import p005b.p199l.p200a.p201a.p248o1.C2285c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.m0.s.g */
/* loaded from: classes.dex */
public final class C2182g implements C2285c0.a<AbstractC2181f> {

    /* renamed from: K */
    public final C2179d f5122K;

    /* renamed from: a */
    public static final Pattern f5096a = Pattern.compile("AVERAGE-BANDWIDTH=(\\d+)\\b");

    /* renamed from: b */
    public static final Pattern f5097b = Pattern.compile("VIDEO=\"(.+?)\"");

    /* renamed from: c */
    public static final Pattern f5098c = Pattern.compile("AUDIO=\"(.+?)\"");

    /* renamed from: d */
    public static final Pattern f5099d = Pattern.compile("SUBTITLES=\"(.+?)\"");

    /* renamed from: e */
    public static final Pattern f5100e = Pattern.compile("CLOSED-CAPTIONS=\"(.+?)\"");

    /* renamed from: f */
    public static final Pattern f5101f = Pattern.compile("[^-]BANDWIDTH=(\\d+)\\b");

    /* renamed from: g */
    public static final Pattern f5102g = Pattern.compile("CHANNELS=\"(.+?)\"");

    /* renamed from: h */
    public static final Pattern f5103h = Pattern.compile("CODECS=\"(.+?)\"");

    /* renamed from: i */
    public static final Pattern f5104i = Pattern.compile("RESOLUTION=(\\d+x\\d+)");

    /* renamed from: j */
    public static final Pattern f5105j = Pattern.compile("FRAME-RATE=([\\d\\.]+)\\b");

    /* renamed from: k */
    public static final Pattern f5106k = Pattern.compile("#EXT-X-TARGETDURATION:(\\d+)\\b");

    /* renamed from: l */
    public static final Pattern f5107l = Pattern.compile("#EXT-X-VERSION:(\\d+)\\b");

    /* renamed from: m */
    public static final Pattern f5108m = Pattern.compile("#EXT-X-PLAYLIST-TYPE:(.+)\\b");

    /* renamed from: n */
    public static final Pattern f5109n = Pattern.compile("#EXT-X-MEDIA-SEQUENCE:(\\d+)\\b");

    /* renamed from: o */
    public static final Pattern f5110o = Pattern.compile("#EXTINF:([\\d\\.]+)\\b");

    /* renamed from: p */
    public static final Pattern f5111p = Pattern.compile("#EXTINF:[\\d\\.]+\\b,(.+)");

    /* renamed from: q */
    public static final Pattern f5112q = Pattern.compile("TIME-OFFSET=(-?[\\d\\.]+)\\b");

    /* renamed from: r */
    public static final Pattern f5113r = Pattern.compile("#EXT-X-BYTERANGE:(\\d+(?:@\\d+)?)\\b");

    /* renamed from: s */
    public static final Pattern f5114s = Pattern.compile("BYTERANGE=\"(\\d+(?:@\\d+)?)\\b\"");

    /* renamed from: t */
    public static final Pattern f5115t = Pattern.compile("METHOD=(NONE|AES-128|SAMPLE-AES|SAMPLE-AES-CENC|SAMPLE-AES-CTR)\\s*(?:,|$)");

    /* renamed from: u */
    public static final Pattern f5116u = Pattern.compile("KEYFORMAT=\"(.+?)\"");

    /* renamed from: v */
    public static final Pattern f5117v = Pattern.compile("KEYFORMATVERSIONS=\"(.+?)\"");

    /* renamed from: w */
    public static final Pattern f5118w = Pattern.compile("URI=\"(.+?)\"");

    /* renamed from: x */
    public static final Pattern f5119x = Pattern.compile("IV=([^,.*]+)");

    /* renamed from: y */
    public static final Pattern f5120y = Pattern.compile("TYPE=(AUDIO|VIDEO|SUBTITLES|CLOSED-CAPTIONS)");

    /* renamed from: z */
    public static final Pattern f5121z = Pattern.compile("LANGUAGE=\"(.+?)\"");

    /* renamed from: A */
    public static final Pattern f5086A = Pattern.compile("NAME=\"(.+?)\"");

    /* renamed from: B */
    public static final Pattern f5087B = Pattern.compile("GROUP-ID=\"(.+?)\"");

    /* renamed from: C */
    public static final Pattern f5088C = Pattern.compile("CHARACTERISTICS=\"(.+?)\"");

    /* renamed from: D */
    public static final Pattern f5089D = Pattern.compile("INSTREAM-ID=\"((?:CC|SERVICE)\\d+)\"");

    /* renamed from: E */
    public static final Pattern f5090E = m1978b("AUTOSELECT");

    /* renamed from: F */
    public static final Pattern f5091F = m1978b("DEFAULT");

    /* renamed from: G */
    public static final Pattern f5092G = m1978b("FORCED");

    /* renamed from: H */
    public static final Pattern f5093H = Pattern.compile("VALUE=\"(.+?)\"");

    /* renamed from: I */
    public static final Pattern f5094I = Pattern.compile("IMPORT=\"(.+?)\"");

    /* renamed from: J */
    public static final Pattern f5095J = Pattern.compile("\\{\\$([a-zA-Z0-9\\-_]+)\\}");

    /* renamed from: b.l.a.a.k1.m0.s.g$a */
    public static class a {

        /* renamed from: a */
        public final BufferedReader f5123a;

        /* renamed from: b */
        public final Queue<String> f5124b;

        /* renamed from: c */
        @Nullable
        public String f5125c;

        public a(Queue<String> queue, BufferedReader bufferedReader) {
            this.f5124b = queue;
            this.f5123a = bufferedReader;
        }

        @EnsuresNonNullIf(expression = {"next"}, result = true)
        /* renamed from: a */
        public boolean m1990a() {
            String trim;
            if (this.f5125c != null) {
                return true;
            }
            if (!this.f5124b.isEmpty()) {
                String poll = this.f5124b.poll();
                Objects.requireNonNull(poll);
                this.f5125c = poll;
                return true;
            }
            do {
                String readLine = this.f5123a.readLine();
                this.f5125c = readLine;
                if (readLine == null) {
                    return false;
                }
                trim = readLine.trim();
                this.f5125c = trim;
            } while (trim.isEmpty());
            return true;
        }

        /* renamed from: b */
        public String m1991b() {
            if (!m1990a()) {
                throw new NoSuchElementException();
            }
            String str = this.f5125c;
            this.f5125c = null;
            return str;
        }
    }

    public C2182g() {
        this.f5122K = C2179d.f5039d;
    }

    /* renamed from: b */
    public static Pattern m1978b(String str) {
        return Pattern.compile(str + "=(NO|YES" + ChineseToPinyinResource.Field.RIGHT_BRACKET);
    }

    @Nullable
    /* renamed from: c */
    public static DrmInitData.SchemeData m1979c(String str, String str2, Map<String, String> map) {
        String m1985i = m1985i(str, f5117v, "1", map);
        if ("urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed".equals(str2)) {
            String m1987k = m1987k(str, f5118w, map);
            return new DrmInitData.SchemeData(C2399v.f6330d, null, "video/mp4", Base64.decode(m1987k.substring(m1987k.indexOf(44)), 0));
        }
        if ("com.widevine".equals(str2)) {
            return new DrmInitData.SchemeData(C2399v.f6330d, null, "hls", C2344d0.m2342t(str));
        }
        if (!"com.microsoft.playready".equals(str2) || !"1".equals(m1985i)) {
            return null;
        }
        String m1987k2 = m1987k(str, f5118w, map);
        byte[] decode = Base64.decode(m1987k2.substring(m1987k2.indexOf(44)), 0);
        UUID uuid = C2399v.f6331e;
        return new DrmInitData.SchemeData(uuid, null, "video/mp4", C4195m.m4844z(uuid, decode));
    }

    /* renamed from: d */
    public static String m1980d(String str) {
        return ("SAMPLE-AES-CENC".equals(str) || "SAMPLE-AES-CTR".equals(str)) ? "cenc" : "cbcs";
    }

    /* renamed from: e */
    public static int m1981e(String str, Pattern pattern) {
        return Integer.parseInt(m1987k(str, pattern, Collections.emptyMap()));
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v5, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r26v0, types: [int] */
    /* JADX WARN: Type inference failed for: r26v1, types: [int] */
    /* JADX WARN: Type inference failed for: r30v0, types: [int] */
    /* JADX WARN: Type inference failed for: r31v1, types: [int] */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v9 */
    /* renamed from: f */
    public static C2179d m1982f(a aVar, String str) {
        ArrayList arrayList;
        boolean z;
        int i2;
        char c2;
        int parseInt;
        String str2;
        C2179d.b bVar;
        String str3;
        int i3;
        C2179d.b bVar2;
        String str4;
        int i4;
        int i5;
        float f2;
        HashMap hashMap;
        HashSet hashSet;
        ArrayList arrayList2;
        ArrayList arrayList3;
        boolean z2;
        int i6;
        int i7;
        String str5 = str;
        HashMap hashMap2 = new HashMap();
        HashMap hashMap3 = new HashMap();
        ArrayList arrayList4 = new ArrayList();
        ArrayList arrayList5 = new ArrayList();
        ArrayList arrayList6 = new ArrayList();
        ArrayList arrayList7 = new ArrayList();
        ArrayList arrayList8 = new ArrayList();
        ArrayList arrayList9 = new ArrayList();
        ArrayList arrayList10 = new ArrayList();
        ArrayList arrayList11 = new ArrayList();
        boolean z3 = false;
        boolean z4 = false;
        while (true) {
            int i8 = -1;
            if (!aVar.m1990a()) {
                ArrayList arrayList12 = arrayList8;
                ArrayList arrayList13 = arrayList11;
                boolean z5 = z4;
                ArrayList arrayList14 = arrayList10;
                ArrayList arrayList15 = new ArrayList();
                HashSet hashSet2 = new HashSet();
                int i9 = 0;
                HashMap hashMap4 = hashMap2;
                while (true) {
                    arrayList = null;
                    if (i9 >= arrayList4.size()) {
                        break;
                    }
                    C2179d.b bVar3 = (C2179d.b) arrayList4.get(i9);
                    if (hashSet2.add(bVar3.f5053a)) {
                        C4195m.m4771I(bVar3.f5054b.f9243j == null);
                        Object obj = hashMap4.get(bVar3.f5053a);
                        Objects.requireNonNull(obj);
                        HlsTrackMetadataEntry hlsTrackMetadataEntry = new HlsTrackMetadataEntry(null, null, (List) obj);
                        Format format = bVar3.f5054b;
                        hashMap = hashMap4;
                        hashSet = hashSet2;
                        arrayList15.add(new C2179d.b(bVar3.f5053a, format.m4042b(format.f9248o, new Metadata(hlsTrackMetadataEntry)), bVar3.f5055c, bVar3.f5056d, bVar3.f5057e, bVar3.f5058f));
                    } else {
                        hashMap = hashMap4;
                        hashSet = hashSet2;
                    }
                    i9++;
                    hashSet2 = hashSet;
                    hashMap4 = hashMap;
                }
                int i10 = 0;
                Format format2 = null;
                while (i10 < arrayList9.size()) {
                    String str6 = (String) arrayList9.get(i10);
                    String m1987k = m1987k(str6, f5087B, hashMap3);
                    String m1987k2 = m1987k(str6, f5086A, hashMap3);
                    String m1986j = m1986j(str6, f5118w, hashMap3);
                    Uri m2514s1 = m1986j == null ? null : C2354n.m2514s1(str5, m1986j);
                    String m1986j2 = m1986j(str6, f5121z, hashMap3);
                    ArrayList arrayList16 = arrayList9;
                    Format format3 = format2;
                    boolean m1984h = m1984h(str6, f5091F, false);
                    ArrayList arrayList17 = arrayList15;
                    boolean z6 = m1984h;
                    if (m1984h(str6, f5092G, false)) {
                        z6 = (m1984h ? 1 : 0) | 2;
                    }
                    boolean z7 = z6;
                    if (m1984h(str6, f5090E, false)) {
                        z7 = (z6 ? 1 : 0) | 4;
                    }
                    String m1986j3 = m1986j(str6, f5088C, hashMap3);
                    if (TextUtils.isEmpty(m1986j3)) {
                        i2 = 0;
                        z = z3;
                    } else {
                        String[] m2316H = C2344d0.m2316H(m1986j3, ChineseToPinyinResource.Field.COMMA);
                        int i11 = C2344d0.m2331i(m2316H, "public.accessibility.describes-video") ? 512 : 0;
                        z = z3;
                        if (C2344d0.m2331i(m2316H, "public.accessibility.transcribes-spoken-dialog")) {
                            i11 |= 4096;
                        }
                        if (C2344d0.m2331i(m2316H, "public.accessibility.describes-music-and-sound")) {
                            i11 |= 1024;
                        }
                        i2 = C2344d0.m2331i(m2316H, "public.easy-to-read") ? i11 | 8192 : i11;
                    }
                    String m639y = C1499a.m639y(m1987k, ":", m1987k2);
                    int i12 = i10;
                    ArrayList arrayList18 = arrayList7;
                    Metadata metadata = new Metadata(new HlsTrackMetadataEntry(m1987k, m1987k2, Collections.emptyList()));
                    String m1987k3 = m1987k(str6, f5120y, hashMap3);
                    switch (m1987k3.hashCode()) {
                        case -959297733:
                            if (m1987k3.equals("SUBTITLES")) {
                                c2 = 0;
                                break;
                            }
                            c2 = 65535;
                            break;
                        case -333210994:
                            if (m1987k3.equals("CLOSED-CAPTIONS")) {
                                c2 = 1;
                                break;
                            }
                            c2 = 65535;
                            break;
                        case 62628790:
                            if (m1987k3.equals("AUDIO")) {
                                c2 = 2;
                                break;
                            }
                            c2 = 65535;
                            break;
                        case 81665115:
                            if (m1987k3.equals("VIDEO")) {
                                c2 = 3;
                                break;
                            }
                            c2 = 65535;
                            break;
                        default:
                            c2 = 65535;
                            break;
                    }
                    if (c2 != 0) {
                        if (c2 != 1) {
                            if (c2 == 2) {
                                int i13 = 0;
                                while (true) {
                                    if (i13 < arrayList4.size()) {
                                        bVar = (C2179d.b) arrayList4.get(i13);
                                        if (!m1987k.equals(bVar.f5056d)) {
                                            i13++;
                                        }
                                    } else {
                                        bVar = null;
                                    }
                                }
                                String m2334l = bVar != null ? C2344d0.m2334l(bVar.f5054b.f9242i, 1) : null;
                                String m2540c = m2334l != null ? C2357q.m2540c(m2334l) : null;
                                String m1986j4 = m1986j(str6, f5102g, hashMap3);
                                if (m1986j4 != null) {
                                    int i14 = C2344d0.f6035a;
                                    int parseInt2 = Integer.parseInt(m1986j4.split("/", 2)[0]);
                                    if ("audio/eac3".equals(m2540c) && m1986j4.endsWith("/JOC")) {
                                        m2540c = "audio/eac3-joc";
                                    }
                                    str3 = m2540c;
                                    i3 = parseInt2;
                                } else {
                                    str3 = m2540c;
                                    i3 = -1;
                                }
                                Format m4037x = Format.m4037x(m639y, m1987k2, "application/x-mpegURL", str3, m2334l, null, -1, i3, -1, null, z7, i2, m1986j2);
                                if (m2514s1 == null) {
                                    format2 = m4037x;
                                } else {
                                    arrayList6.add(new C2179d.a(m2514s1, m4037x.m4042b(m4037x.f9248o, metadata), m1987k, m1987k2));
                                }
                            } else if (c2 == 3) {
                                int i15 = 0;
                                while (true) {
                                    if (i15 < arrayList4.size()) {
                                        bVar2 = (C2179d.b) arrayList4.get(i15);
                                        if (!m1987k.equals(bVar2.f5055c)) {
                                            i15++;
                                        }
                                    } else {
                                        bVar2 = null;
                                    }
                                }
                                if (bVar2 != null) {
                                    Format format4 = bVar2.f5054b;
                                    String m2334l2 = C2344d0.m2334l(format4.f9242i, 2);
                                    int i16 = format4.f9250q;
                                    int i17 = format4.f9251r;
                                    f2 = format4.f9252s;
                                    str4 = m2334l2;
                                    i4 = i16;
                                    i5 = i17;
                                } else {
                                    str4 = null;
                                    i4 = -1;
                                    i5 = -1;
                                    f2 = -1.0f;
                                }
                                Format m4033J = Format.m4033J(m639y, m1987k2, "application/x-mpegURL", str4 != null ? C2357q.m2540c(str4) : null, str4, null, -1, i4, i5, f2, null, z7, i2);
                                Format m4042b = m4033J.m4042b(m4033J.f9248o, metadata);
                                if (m2514s1 != null) {
                                    arrayList5.add(new C2179d.a(m2514s1, m4042b, m1987k, m1987k2));
                                }
                            }
                            arrayList7 = arrayList18;
                        } else {
                            String m1987k4 = m1987k(str6, f5089D, hashMap3);
                            if (m1987k4.startsWith("CC")) {
                                parseInt = Integer.parseInt(m1987k4.substring(2));
                                str2 = "application/cea-608";
                            } else {
                                parseInt = Integer.parseInt(m1987k4.substring(7));
                                str2 = "application/cea-708";
                            }
                            int i18 = parseInt;
                            String str7 = str2;
                            if (arrayList == null) {
                                arrayList = new ArrayList();
                            }
                            arrayList.add(Format.m4030G(m639y, m1987k2, null, str7, null, -1, z7, i2, m1986j2, i18));
                            format2 = format3;
                        }
                        arrayList7 = arrayList18;
                        i10 = i12 + 1;
                        str5 = str;
                        arrayList9 = arrayList16;
                        arrayList15 = arrayList17;
                        z3 = z;
                    } else {
                        Format m4029F = Format.m4029F(m639y, m1987k2, "application/x-mpegURL", "text/vtt", null, -1, z7, i2, m1986j2);
                        arrayList7 = arrayList18;
                        arrayList7.add(new C2179d.a(m2514s1, m4029F.m4042b(m4029F.f9248o, metadata), m1987k, m1987k2));
                    }
                    format2 = format3;
                    i10 = i12 + 1;
                    str5 = str;
                    arrayList9 = arrayList16;
                    arrayList15 = arrayList17;
                    z3 = z;
                }
                return new C2179d(str, arrayList13, arrayList15, arrayList5, arrayList6, arrayList7, arrayList12, format2, z3 ? Collections.emptyList() : arrayList, z5, hashMap3, arrayList14);
            }
            String m1991b = aVar.m1991b();
            if (m1991b.startsWith("#EXT")) {
                arrayList11.add(m1991b);
            }
            if (m1991b.startsWith("#EXT-X-DEFINE")) {
                hashMap3.put(m1987k(m1991b, f5086A, hashMap3), m1987k(m1991b, f5093H, hashMap3));
            } else if (m1991b.equals("#EXT-X-INDEPENDENT-SEGMENTS")) {
                z4 = true;
            } else if (m1991b.startsWith("#EXT-X-MEDIA")) {
                arrayList9.add(m1991b);
            } else {
                if (m1991b.startsWith("#EXT-X-SESSION-KEY")) {
                    DrmInitData.SchemeData m1979c = m1979c(m1991b, m1985i(m1991b, f5116u, "identity", hashMap3), hashMap3);
                    if (m1979c != null) {
                        z2 = z4;
                        arrayList2 = arrayList8;
                        arrayList10.add(new DrmInitData(m1980d(m1987k(m1991b, f5115t, hashMap3)), true, m1979c));
                    } else {
                        arrayList2 = arrayList8;
                        z2 = z4;
                    }
                } else {
                    arrayList2 = arrayList8;
                    z2 = z4;
                    if (m1991b.startsWith("#EXT-X-STREAM-INF")) {
                        boolean contains = z3 | m1991b.contains("CLOSED-CAPTIONS=NONE");
                        int m1981e = m1981e(m1991b, f5101f);
                        Matcher matcher = f5096a.matcher(m1991b);
                        if (matcher.find()) {
                            Integer.parseInt(matcher.group(1));
                        }
                        String m1986j5 = m1986j(m1991b, f5103h, hashMap3);
                        String m1986j6 = m1986j(m1991b, f5104i, hashMap3);
                        if (m1986j6 != null) {
                            String[] split = m1986j6.split("x");
                            int parseInt3 = Integer.parseInt(split[0]);
                            int parseInt4 = Integer.parseInt(split[1]);
                            if (parseInt3 <= 0 || parseInt4 <= 0) {
                                parseInt3 = -1;
                            } else {
                                i8 = parseInt4;
                            }
                            i7 = i8;
                            i6 = parseInt3;
                        } else {
                            i6 = -1;
                            i7 = -1;
                        }
                        String m1986j7 = m1986j(m1991b, f5105j, hashMap3);
                        float parseFloat = m1986j7 != null ? Float.parseFloat(m1986j7) : -1.0f;
                        String m1986j8 = m1986j(m1991b, f5097b, hashMap3);
                        String m1986j9 = m1986j(m1991b, f5098c, hashMap3);
                        String m1986j10 = m1986j(m1991b, f5099d, hashMap3);
                        String m1986j11 = m1986j(m1991b, f5100e, hashMap3);
                        if (!aVar.m1990a()) {
                            throw new C2205l0("#EXT-X-STREAM-INF tag must be followed by another line");
                        }
                        Uri m2514s12 = C2354n.m2514s1(str5, m1988l(aVar.m1991b(), hashMap3));
                        ArrayList arrayList19 = arrayList10;
                        arrayList4.add(new C2179d.b(m2514s12, Format.m4033J(Integer.toString(arrayList4.size()), null, "application/x-mpegURL", null, m1986j5, null, m1981e, i6, i7, parseFloat, null, 0, 0), m1986j8, m1986j9, m1986j10, m1986j11));
                        ArrayList arrayList20 = (ArrayList) hashMap2.get(m2514s12);
                        if (arrayList20 == null) {
                            arrayList20 = new ArrayList();
                            hashMap2.put(m2514s12, arrayList20);
                        }
                        arrayList20.add(new HlsTrackMetadataEntry.VariantInfo(m1981e, m1986j8, m1986j9, m1986j10, m1986j11));
                        z4 = z2;
                        arrayList8 = arrayList2;
                        arrayList10 = arrayList19;
                        arrayList11 = arrayList11;
                        z3 = contains;
                    }
                }
                arrayList3 = arrayList11;
                z4 = z2;
                arrayList8 = arrayList2;
                arrayList10 = arrayList10;
                arrayList11 = arrayList3;
            }
            arrayList2 = arrayList8;
            arrayList3 = arrayList11;
            z2 = z4;
            z4 = z2;
            arrayList8 = arrayList2;
            arrayList10 = arrayList10;
            arrayList11 = arrayList3;
        }
    }

    /* renamed from: g */
    public static C2180e m1983g(C2179d c2179d, a aVar, String str) {
        long j2;
        long j3;
        String m1986j;
        long j4;
        TreeMap treeMap;
        String str2;
        long j5;
        DrmInitData drmInitData;
        DrmInitData drmInitData2;
        C2179d c2179d2 = c2179d;
        boolean z = c2179d2.f5085c;
        HashMap hashMap = new HashMap();
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        TreeMap treeMap2 = new TreeMap();
        long j6 = -9223372036854775807L;
        long j7 = -9223372036854775807L;
        boolean z2 = false;
        int i2 = 0;
        String str3 = null;
        String str4 = null;
        long j8 = 0;
        DrmInitData drmInitData3 = null;
        int i3 = 0;
        long j9 = 0;
        int i4 = 1;
        boolean z3 = false;
        long j10 = 0;
        String str5 = null;
        int i5 = 0;
        long j11 = 0;
        DrmInitData drmInitData4 = null;
        C2180e.a aVar2 = null;
        long j12 = 0;
        while (true) {
            String str6 = str4;
            String str7 = str5;
            C2180e.a aVar3 = aVar2;
            long j13 = -1;
            boolean z4 = false;
            long j14 = 0;
            String str8 = "";
            long j15 = j10;
            boolean z5 = z3;
            int i6 = i4;
            long j16 = j9;
            long j17 = j7;
            int i7 = i2;
            String str9 = str3;
            long j18 = j17;
            int i8 = i3;
            long j19 = j8;
            while (aVar.m1990a()) {
                String m1991b = aVar.m1991b();
                if (m1991b.startsWith("#EXT")) {
                    arrayList2.add(m1991b);
                }
                if (m1991b.startsWith("#EXT-X-PLAYLIST-TYPE")) {
                    String m1987k = m1987k(m1991b, f5108m, hashMap);
                    if ("VOD".equals(m1987k)) {
                        i7 = 1;
                    } else if ("EVENT".equals(m1987k)) {
                        i7 = 2;
                    }
                } else if (m1991b.startsWith("#EXT-X-START")) {
                    j6 = (long) (Double.parseDouble(m1987k(m1991b, f5112q, Collections.emptyMap())) * 1000000.0d);
                } else {
                    boolean z6 = z;
                    if (m1991b.startsWith("#EXT-X-MAP")) {
                        String m1987k2 = m1987k(m1991b, f5118w, hashMap);
                        boolean z7 = z2;
                        String m1986j2 = m1986j(m1991b, f5114s, hashMap);
                        if (m1986j2 != null) {
                            String[] split = m1986j2.split("@");
                            long parseLong = Long.parseLong(split[0]);
                            if (split.length > 1) {
                                j15 = Long.parseLong(split[1]);
                            }
                            j2 = j15;
                            j3 = parseLong;
                        } else {
                            j2 = j15;
                            j3 = j13;
                        }
                        if (str9 != null && str7 == null) {
                            throw new C2205l0("The encryption IV attribute must be present when an initialization segment is encrypted with METHOD=AES-128.");
                        }
                        aVar3 = new C2180e.a(m1987k2, null, "", 0L, -1, -9223372036854775807L, null, str9, str7, j2, j3, false);
                        j13 = -1;
                        z = z6;
                        z2 = z7;
                        j15 = 0;
                    } else {
                        boolean z8 = z2;
                        if (m1991b.startsWith("#EXT-X-TARGETDURATION")) {
                            j18 = 1000000 * m1981e(m1991b, f5106k);
                        } else if (m1991b.startsWith("#EXT-X-MEDIA-SEQUENCE")) {
                            j16 = Long.parseLong(m1987k(m1991b, f5109n, Collections.emptyMap()));
                            j11 = j16;
                        } else if (m1991b.startsWith("#EXT-X-VERSION")) {
                            i6 = m1981e(m1991b, f5107l);
                        } else {
                            if (m1991b.startsWith("#EXT-X-DEFINE")) {
                                String m1986j3 = m1986j(m1991b, f5094I, hashMap);
                                if (m1986j3 != null) {
                                    String str10 = c2179d2.f5048m.get(m1986j3);
                                    if (str10 != null) {
                                        hashMap.put(m1986j3, str10);
                                    }
                                } else {
                                    hashMap.put(m1987k(m1991b, f5086A, hashMap), m1987k(m1991b, f5093H, hashMap));
                                }
                            } else if (m1991b.startsWith("#EXTINF")) {
                                long parseDouble = (long) (Double.parseDouble(m1987k(m1991b, f5110o, Collections.emptyMap())) * 1000000.0d);
                                str8 = m1985i(m1991b, f5111p, "", hashMap);
                                j14 = parseDouble;
                            } else if (m1991b.startsWith("#EXT-X-KEY")) {
                                String m1987k3 = m1987k(m1991b, f5115t, hashMap);
                                String m1985i = m1985i(m1991b, f5116u, "identity", hashMap);
                                if ("NONE".equals(m1987k3)) {
                                    treeMap2.clear();
                                    m1986j = null;
                                } else {
                                    m1986j = m1986j(m1991b, f5119x, hashMap);
                                    if (!"identity".equals(m1985i)) {
                                        if (str6 == null) {
                                            str6 = m1980d(m1987k3);
                                        }
                                        DrmInitData.SchemeData m1979c = m1979c(m1991b, m1985i, hashMap);
                                        if (m1979c != null) {
                                            treeMap2.put(m1985i, m1979c);
                                        }
                                    } else if ("AES-128".equals(m1987k3)) {
                                        str9 = m1987k(m1991b, f5118w, hashMap);
                                        str7 = m1986j;
                                    }
                                    str7 = m1986j;
                                    z2 = z8;
                                    str9 = null;
                                    c2179d2 = c2179d;
                                    z = z6;
                                }
                                str7 = m1986j;
                                z2 = z8;
                                str9 = null;
                                drmInitData4 = null;
                                c2179d2 = c2179d;
                                z = z6;
                            } else if (m1991b.startsWith("#EXT-X-BYTERANGE")) {
                                String[] split2 = m1987k(m1991b, f5113r, hashMap).split("@");
                                j13 = Long.parseLong(split2[0]);
                                if (split2.length > 1) {
                                    j15 = Long.parseLong(split2[1]);
                                }
                            } else if (m1991b.startsWith("#EXT-X-DISCONTINUITY-SEQUENCE")) {
                                i8 = Integer.parseInt(m1991b.substring(m1991b.indexOf(58) + 1));
                                z2 = true;
                                c2179d2 = c2179d;
                                z = z6;
                            } else if (m1991b.equals("#EXT-X-DISCONTINUITY")) {
                                i5++;
                            } else if (m1991b.startsWith("#EXT-X-PROGRAM-DATE-TIME")) {
                                if (j19 == 0) {
                                    j19 = C2399v.m2668a(C2344d0.m2311C(m1991b.substring(m1991b.indexOf(58) + 1))) - j12;
                                }
                            } else if (m1991b.equals("#EXT-X-GAP")) {
                                c2179d2 = c2179d;
                                z = z6;
                                z2 = z8;
                                z4 = true;
                            } else if (m1991b.equals("#EXT-X-INDEPENDENT-SEGMENTS")) {
                                z = true;
                                c2179d2 = c2179d;
                                z2 = z8;
                            } else if (m1991b.equals("#EXT-X-ENDLIST")) {
                                c2179d2 = c2179d;
                                z = z6;
                                z2 = z8;
                                z5 = true;
                            } else if (!m1991b.startsWith("#")) {
                                String hexString = str9 == null ? null : str7 != null ? str7 : Long.toHexString(j11);
                                long j20 = j11 + 1;
                                if (j13 == -1) {
                                    j15 = 0;
                                }
                                if (drmInitData4 != null || treeMap2.isEmpty()) {
                                    j4 = j20;
                                    treeMap = treeMap2;
                                    str2 = str7;
                                    j5 = j6;
                                    drmInitData = drmInitData4;
                                } else {
                                    j4 = j20;
                                    int i9 = 0;
                                    DrmInitData.SchemeData[] schemeDataArr = (DrmInitData.SchemeData[]) treeMap2.values().toArray(new DrmInitData.SchemeData[0]);
                                    DrmInitData drmInitData5 = new DrmInitData(str6, true, schemeDataArr);
                                    if (drmInitData3 == null) {
                                        DrmInitData.SchemeData[] schemeDataArr2 = new DrmInitData.SchemeData[schemeDataArr.length];
                                        drmInitData2 = drmInitData5;
                                        while (i9 < schemeDataArr.length) {
                                            DrmInitData.SchemeData schemeData = schemeDataArr[i9];
                                            schemeDataArr2[i9] = new DrmInitData.SchemeData(schemeData.f9265e, schemeData.f9266f, schemeData.f9267g, null);
                                            i9++;
                                            schemeDataArr = schemeDataArr;
                                            treeMap2 = treeMap2;
                                            str7 = str7;
                                            j6 = j6;
                                        }
                                        treeMap = treeMap2;
                                        str2 = str7;
                                        j5 = j6;
                                        drmInitData3 = new DrmInitData(str6, true, schemeDataArr2);
                                    } else {
                                        drmInitData2 = drmInitData5;
                                        treeMap = treeMap2;
                                        str2 = str7;
                                        j5 = j6;
                                    }
                                    drmInitData = drmInitData2;
                                }
                                arrayList.add(new C2180e.a(m1988l(m1991b, hashMap), aVar3, str8, j14, i5, j12, drmInitData, str9, hexString, j15, j13, z4));
                                j12 += j14;
                                if (j13 != -1) {
                                    j15 += j13;
                                }
                                drmInitData4 = drmInitData;
                                str4 = str6;
                                aVar2 = aVar3;
                                j11 = j4;
                                treeMap2 = treeMap;
                                j6 = j5;
                                z = z6;
                                z2 = z8;
                                c2179d2 = c2179d;
                                long j21 = j18;
                                i2 = i7;
                                str3 = str9;
                                j7 = j21;
                                long j22 = j19;
                                i3 = i8;
                                j8 = j22;
                                j9 = j16;
                                i4 = i6;
                                z3 = z5;
                                j10 = j15;
                                str5 = str2;
                            }
                            c2179d2 = c2179d;
                            treeMap2 = treeMap2;
                            str7 = str7;
                            j6 = j6;
                            z = z6;
                            z2 = z8;
                        }
                        z2 = z8;
                        c2179d2 = c2179d;
                        z = z6;
                    }
                }
            }
            return new C2180e(i7, str, arrayList2, j6, j19, z2, i8, j16, i6, j18, z, z5, j19 != 0, drmInitData3, arrayList);
        }
    }

    /* renamed from: h */
    public static boolean m1984h(String str, Pattern pattern, boolean z) {
        Matcher matcher = pattern.matcher(str);
        return matcher.find() ? matcher.group(1).equals("YES") : z;
    }

    /* renamed from: i */
    public static String m1985i(String str, Pattern pattern, String str2, Map<String, String> map) {
        Matcher matcher = pattern.matcher(str);
        if (matcher.find()) {
            str2 = matcher.group(1);
        }
        return (map.isEmpty() || str2 == null) ? str2 : m1988l(str2, map);
    }

    @Nullable
    /* renamed from: j */
    public static String m1986j(String str, Pattern pattern, Map<String, String> map) {
        return m1985i(str, pattern, null, map);
    }

    /* renamed from: k */
    public static String m1987k(String str, Pattern pattern, Map<String, String> map) {
        String m1985i = m1985i(str, pattern, null, map);
        if (m1985i != null) {
            return m1985i;
        }
        StringBuilder m586H = C1499a.m586H("Couldn't match ");
        m586H.append(pattern.pattern());
        m586H.append(" in ");
        m586H.append(str);
        throw new C2205l0(m586H.toString());
    }

    /* renamed from: l */
    public static String m1988l(String str, Map<String, String> map) {
        Matcher matcher = f5095J.matcher(str);
        StringBuffer stringBuffer = new StringBuffer();
        while (matcher.find()) {
            String group = matcher.group(1);
            if (map.containsKey(group)) {
                matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(map.get(group)));
            }
        }
        matcher.appendTail(stringBuffer);
        return stringBuffer.toString();
    }

    /* renamed from: m */
    public static int m1989m(BufferedReader bufferedReader, boolean z, int i2) {
        while (i2 != -1 && Character.isWhitespace(i2) && (z || !C2344d0.m2347y(i2))) {
            i2 = bufferedReader.read();
        }
        return i2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x0050, code lost:
    
        r1 = r0.readLine();
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0054, code lost:
    
        if (r1 == null) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x0056, code lost:
    
        r1 = r1.trim();
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x005e, code lost:
    
        if (r1.isEmpty() == false) goto L72;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0067, code lost:
    
        if (r1.startsWith("#EXT-X-STREAM-INF") == false) goto L30;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0085, code lost:
    
        if (r1.startsWith("#EXT-X-TARGETDURATION") != false) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x008d, code lost:
    
        if (r1.startsWith("#EXT-X-MEDIA-SEQUENCE") != false) goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0095, code lost:
    
        if (r1.startsWith("#EXTINF") != false) goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x009d, code lost:
    
        if (r1.startsWith("#EXT-X-KEY") != false) goto L81;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x00a5, code lost:
    
        if (r1.startsWith("#EXT-X-BYTERANGE") != false) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00ad, code lost:
    
        if (r1.equals("#EXT-X-DISCONTINUITY") != false) goto L76;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00b5, code lost:
    
        if (r1.equals("#EXT-X-DISCONTINUITY-SEQUENCE") != false) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00bd, code lost:
    
        if (r1.equals("#EXT-X-ENDLIST") == false) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00c0, code lost:
    
        r8.add(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00c4, code lost:
    
        r8.add(r1);
        r7 = m1983g(r6.f5122K, new p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2182g.a(r8, r0), r7.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x007b, code lost:
    
        r0.close();
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0069, code lost:
    
        r8.add(r1);
        r7 = m1982f(new p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2182g.a(r8, r0), r7.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00da, code lost:
    
        r0.close();
     */
    @Override // p005b.p199l.p200a.p201a.p248o1.C2285c0.a
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.AbstractC2181f mo1900a(android.net.Uri r7, java.io.InputStream r8) {
        /*
            r6 = this;
            java.io.BufferedReader r0 = new java.io.BufferedReader
            java.io.InputStreamReader r1 = new java.io.InputStreamReader
            r1.<init>(r8)
            r0.<init>(r1)
            java.util.ArrayDeque r8 = new java.util.ArrayDeque
            r8.<init>()
            int r1 = r0.read()     // Catch: java.lang.Throwable -> Led
            r2 = 239(0xef, float:3.35E-43)
            r3 = 0
            if (r1 != r2) goto L2d
            int r1 = r0.read()     // Catch: java.lang.Throwable -> Led
            r2 = 187(0xbb, float:2.62E-43)
            if (r1 != r2) goto L4e
            int r1 = r0.read()     // Catch: java.lang.Throwable -> Led
            r2 = 191(0xbf, float:2.68E-43)
            if (r1 == r2) goto L29
            goto L4e
        L29:
            int r1 = r0.read()     // Catch: java.lang.Throwable -> Led
        L2d:
            r2 = 1
            int r1 = m1989m(r0, r2, r1)     // Catch: java.lang.Throwable -> Led
            r2 = 7
            r4 = 0
        L34:
            if (r4 >= r2) goto L46
            java.lang.String r5 = "#EXTM3U"
            char r5 = r5.charAt(r4)     // Catch: java.lang.Throwable -> Led
            if (r1 == r5) goto L3f
            goto L4e
        L3f:
            int r1 = r0.read()     // Catch: java.lang.Throwable -> Led
            int r4 = r4 + 1
            goto L34
        L46:
            int r1 = m1989m(r0, r3, r1)     // Catch: java.lang.Throwable -> Led
            boolean r3 = p005b.p199l.p200a.p201a.p250p1.C2344d0.m2347y(r1)     // Catch: java.lang.Throwable -> Led
        L4e:
            if (r3 == 0) goto Le5
        L50:
            java.lang.String r1 = r0.readLine()     // Catch: java.lang.Throwable -> Led
            if (r1 == 0) goto Ld8
            java.lang.String r1 = r1.trim()     // Catch: java.lang.Throwable -> Led
            boolean r2 = r1.isEmpty()     // Catch: java.lang.Throwable -> Led
            if (r2 == 0) goto L61
            goto L50
        L61:
            java.lang.String r2 = "#EXT-X-STREAM-INF"
            boolean r2 = r1.startsWith(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 == 0) goto L7f
            r8.add(r1)     // Catch: java.lang.Throwable -> Led
            b.l.a.a.k1.m0.s.g$a r1 = new b.l.a.a.k1.m0.s.g$a     // Catch: java.lang.Throwable -> Led
            r1.<init>(r8, r0)     // Catch: java.lang.Throwable -> Led
            java.lang.String r7 = r7.toString()     // Catch: java.lang.Throwable -> Led
            b.l.a.a.k1.m0.s.d r7 = m1982f(r1, r7)     // Catch: java.lang.Throwable -> Led
        L79:
            int r8 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            r0.close()     // Catch: java.io.IOException -> Ld7
            goto Ld7
        L7f:
            java.lang.String r2 = "#EXT-X-TARGETDURATION"
            boolean r2 = r1.startsWith(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 != 0) goto Lc4
            java.lang.String r2 = "#EXT-X-MEDIA-SEQUENCE"
            boolean r2 = r1.startsWith(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 != 0) goto Lc4
            java.lang.String r2 = "#EXTINF"
            boolean r2 = r1.startsWith(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 != 0) goto Lc4
            java.lang.String r2 = "#EXT-X-KEY"
            boolean r2 = r1.startsWith(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 != 0) goto Lc4
            java.lang.String r2 = "#EXT-X-BYTERANGE"
            boolean r2 = r1.startsWith(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 != 0) goto Lc4
            java.lang.String r2 = "#EXT-X-DISCONTINUITY"
            boolean r2 = r1.equals(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 != 0) goto Lc4
            java.lang.String r2 = "#EXT-X-DISCONTINUITY-SEQUENCE"
            boolean r2 = r1.equals(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 != 0) goto Lc4
            java.lang.String r2 = "#EXT-X-ENDLIST"
            boolean r2 = r1.equals(r2)     // Catch: java.lang.Throwable -> Led
            if (r2 == 0) goto Lc0
            goto Lc4
        Lc0:
            r8.add(r1)     // Catch: java.lang.Throwable -> Led
            goto L50
        Lc4:
            r8.add(r1)     // Catch: java.lang.Throwable -> Led
            b.l.a.a.k1.m0.s.d r1 = r6.f5122K     // Catch: java.lang.Throwable -> Led
            b.l.a.a.k1.m0.s.g$a r2 = new b.l.a.a.k1.m0.s.g$a     // Catch: java.lang.Throwable -> Led
            r2.<init>(r8, r0)     // Catch: java.lang.Throwable -> Led
            java.lang.String r7 = r7.toString()     // Catch: java.lang.Throwable -> Led
            b.l.a.a.k1.m0.s.e r7 = m1983g(r1, r2, r7)     // Catch: java.lang.Throwable -> Led
            goto L79
        Ld7:
            return r7
        Ld8:
            int r7 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            r0.close()     // Catch: java.io.IOException -> Ldd
        Ldd:
            b.l.a.a.l0 r7 = new b.l.a.a.l0
            java.lang.String r8 = "Failed to parse the playlist, could not identify any tags."
            r7.<init>(r8)
            throw r7
        Le5:
            b.l.a.a.k1.i0 r8 = new b.l.a.a.k1.i0     // Catch: java.lang.Throwable -> Led
            java.lang.String r1 = "Input does not start with the #EXTM3U header."
            r8.<init>(r1, r7)     // Catch: java.lang.Throwable -> Led
            throw r8     // Catch: java.lang.Throwable -> Led
        Led:
            r7 = move-exception
            int r8 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            r0.close()     // Catch: java.io.IOException -> Lf3
        Lf3:
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2182g.mo1900a(android.net.Uri, java.io.InputStream):java.lang.Object");
    }

    public C2182g(C2179d c2179d) {
        this.f5122K = c2179d;
    }
}
