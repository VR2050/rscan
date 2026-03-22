package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import android.net.Uri;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import androidx.exifinterface.media.ExifInterface;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.xml.sax.helpers.DefaultHandler;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2153j;
import p005b.p199l.p200a.p201a.p248o1.C2285c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.l0.k.c */
/* loaded from: classes.dex */
public class C2146c extends DefaultHandler implements C2285c0.a<C2145b> {

    /* renamed from: a */
    public static final Pattern f4792a = Pattern.compile("(\\d+)(?:/(\\d+))?");

    /* renamed from: b */
    public static final Pattern f4793b = Pattern.compile("CC([1-4])=.*");

    /* renamed from: c */
    public static final Pattern f4794c = Pattern.compile("([1-9]|[1-5][0-9]|6[0-3])=.*");

    /* renamed from: d */
    public final XmlPullParserFactory f4795d;

    /* renamed from: b.l.a.a.k1.l0.k.c$a */
    public static final class a {

        /* renamed from: a */
        public final Format f4796a;

        /* renamed from: b */
        public final String f4797b;

        /* renamed from: c */
        public final AbstractC2153j f4798c;

        /* renamed from: d */
        @Nullable
        public final String f4799d;

        /* renamed from: e */
        public final ArrayList<DrmInitData.SchemeData> f4800e;

        /* renamed from: f */
        public final ArrayList<C2147d> f4801f;

        /* renamed from: g */
        public final long f4802g;

        public a(Format format, String str, AbstractC2153j abstractC2153j, @Nullable String str2, ArrayList<DrmInitData.SchemeData> arrayList, ArrayList<C2147d> arrayList2, long j2) {
            this.f4796a = format;
            this.f4797b = str;
            this.f4798c = abstractC2153j;
            this.f4799d = str2;
            this.f4800e = arrayList;
            this.f4801f = arrayList2;
            this.f4802g = j2;
        }
    }

    public C2146c() {
        try {
            this.f4795d = XmlPullParserFactory.newInstance();
        } catch (XmlPullParserException e2) {
            throw new RuntimeException("Couldn't create XmlPullParserFactory instance", e2);
        }
    }

    /* renamed from: c */
    public static int m1891c(int i2, int i3) {
        if (i2 == -1) {
            return i3;
        }
        if (i3 == -1) {
            return i2;
        }
        C4195m.m4771I(i2 == i3);
        return i2;
    }

    /* renamed from: d */
    public static void m1892d(XmlPullParser xmlPullParser) {
        if (C2354n.m2420P0(xmlPullParser)) {
            int i2 = 1;
            while (i2 != 0) {
                xmlPullParser.next();
                if (C2354n.m2420P0(xmlPullParser)) {
                    i2++;
                } else {
                    if (xmlPullParser.getEventType() == 3) {
                        i2--;
                    }
                }
            }
        }
    }

    /* renamed from: e */
    public static boolean m1893e(@Nullable String str) {
        return C2357q.m2546i(str) || "application/ttml+xml".equals(str) || "application/x-mp4-vtt".equals(str) || "application/cea-708".equals(str) || "application/cea-608".equals(str);
    }

    /* renamed from: k */
    public static C2147d m1894k(XmlPullParser xmlPullParser, String str) {
        String attributeValue = xmlPullParser.getAttributeValue(null, "schemeIdUri");
        if (attributeValue == null) {
            attributeValue = "";
        }
        String attributeValue2 = xmlPullParser.getAttributeValue(null, "value");
        if (attributeValue2 == null) {
            attributeValue2 = null;
        }
        String attributeValue3 = xmlPullParser.getAttributeValue(null, "id");
        String str2 = attributeValue3 != null ? attributeValue3 : null;
        do {
            xmlPullParser.next();
        } while (!C2354n.m2408L0(xmlPullParser, str));
        return new C2147d(attributeValue, attributeValue2, str2);
    }

    /* renamed from: l */
    public static long m1895l(XmlPullParser xmlPullParser, String str, long j2) {
        String attributeValue = xmlPullParser.getAttributeValue(null, str);
        if (attributeValue == null) {
            return j2;
        }
        Matcher matcher = C2344d0.f6042h.matcher(attributeValue);
        if (!matcher.matches()) {
            return (long) (Double.parseDouble(attributeValue) * 3600.0d * 1000.0d);
        }
        boolean isEmpty = true ^ TextUtils.isEmpty(matcher.group(1));
        String group = matcher.group(3);
        double d2 = ShadowDrawableWrapper.COS_45;
        double parseDouble = group != null ? Double.parseDouble(group) * 3.1556908E7d : 0.0d;
        String group2 = matcher.group(5);
        double parseDouble2 = parseDouble + (group2 != null ? Double.parseDouble(group2) * 2629739.0d : 0.0d);
        String group3 = matcher.group(7);
        double parseDouble3 = parseDouble2 + (group3 != null ? Double.parseDouble(group3) * 86400.0d : 0.0d);
        String group4 = matcher.group(10);
        double parseDouble4 = parseDouble3 + (group4 != null ? Double.parseDouble(group4) * 3600.0d : 0.0d);
        String group5 = matcher.group(12);
        double parseDouble5 = parseDouble4 + (group5 != null ? Double.parseDouble(group5) * 60.0d : 0.0d);
        String group6 = matcher.group(14);
        if (group6 != null) {
            d2 = Double.parseDouble(group6);
        }
        long j3 = (long) ((parseDouble5 + d2) * 1000.0d);
        return isEmpty ? -j3 : j3;
    }

    /* renamed from: m */
    public static float m1896m(XmlPullParser xmlPullParser, float f2) {
        String attributeValue = xmlPullParser.getAttributeValue(null, "frameRate");
        if (attributeValue == null) {
            return f2;
        }
        Matcher matcher = f4792a.matcher(attributeValue);
        if (!matcher.matches()) {
            return f2;
        }
        int parseInt = Integer.parseInt(matcher.group(1));
        return !TextUtils.isEmpty(matcher.group(2)) ? parseInt / Integer.parseInt(r2) : parseInt;
    }

    /* renamed from: n */
    public static int m1897n(XmlPullParser xmlPullParser, String str, int i2) {
        String attributeValue = xmlPullParser.getAttributeValue(null, str);
        return attributeValue == null ? i2 : Integer.parseInt(attributeValue);
    }

    /* renamed from: o */
    public static long m1898o(XmlPullParser xmlPullParser, String str, long j2) {
        String attributeValue = xmlPullParser.getAttributeValue(null, str);
        return attributeValue == null ? j2 : Long.parseLong(attributeValue);
    }

    /* renamed from: v */
    public static String m1899v(XmlPullParser xmlPullParser, String str) {
        String str2 = "";
        do {
            xmlPullParser.next();
            if (xmlPullParser.getEventType() == 4) {
                str2 = xmlPullParser.getText();
            } else {
                m1892d(xmlPullParser);
            }
        } while (!C2354n.m2408L0(xmlPullParser, str));
        return str2;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2285c0.a
    /* renamed from: a */
    public C2145b mo1900a(Uri uri, InputStream inputStream) {
        try {
            XmlPullParser newPullParser = this.f4795d.newPullParser();
            newPullParser.setInput(inputStream, null);
            if (newPullParser.next() == 2 && "MPD".equals(newPullParser.getName())) {
                return m1907p(newPullParser, uri.toString());
            }
            throw new C2205l0("inputStream does not contain a valid media presentation description");
        } catch (XmlPullParserException e2) {
            throw new C2205l0(e2);
        }
    }

    /* renamed from: b */
    public final long m1901b(List<AbstractC2153j.d> list, long j2, long j3, int i2, long j4) {
        int i3;
        if (i2 >= 0) {
            i3 = i2 + 1;
        } else {
            int i4 = C2344d0.f6035a;
            i3 = (int) ((((j4 - j2) + j3) - 1) / j3);
        }
        for (int i5 = 0; i5 < i3; i5++) {
            list.add(new AbstractC2153j.d(j2, j3));
            j2 += j3;
        }
        return j2;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* renamed from: f */
    public int m1902f(XmlPullParser xmlPullParser) {
        String m2320L;
        char c2;
        String attributeValue = xmlPullParser.getAttributeValue(null, "schemeIdUri");
        if (attributeValue == null) {
            attributeValue = null;
        }
        int i2 = -1;
        if ("urn:mpeg:dash:23003:3:audio_channel_configuration:2011".equals(attributeValue)) {
            i2 = m1897n(xmlPullParser, "value", -1);
        } else if (("tag:dolby.com,2014:dash:audio_channel_configuration:2011".equals(attributeValue) || "urn:dolby:dash:audio_channel_configuration:2011".equals(attributeValue)) && (m2320L = C2344d0.m2320L(xmlPullParser.getAttributeValue(null, "value"))) != null) {
            switch (m2320L.hashCode()) {
                case 1596796:
                    if (m2320L.equals("4000")) {
                        c2 = 0;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 2937391:
                    if (m2320L.equals("a000")) {
                        c2 = 1;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 3094035:
                    if (m2320L.equals("f801")) {
                        c2 = 2;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 3133436:
                    if (m2320L.equals("fa01")) {
                        c2 = 3;
                        break;
                    }
                    c2 = 65535;
                    break;
                default:
                    c2 = 65535;
                    break;
            }
            if (c2 == 0) {
                i2 = 1;
            } else if (c2 == 1) {
                i2 = 2;
            } else if (c2 == 2) {
                i2 = 6;
            } else if (c2 == 3) {
                i2 = 8;
            }
        }
        do {
            xmlPullParser.next();
        } while (!C2354n.m2408L0(xmlPullParser, "AudioChannelConfiguration"));
        return i2;
    }

    /* renamed from: g */
    public String m1903g(XmlPullParser xmlPullParser, String str) {
        return C2354n.m2511r1(str, m1899v(xmlPullParser, "BaseURL"));
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x004d  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00c7  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0143  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x010a  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x00b3  */
    /* renamed from: h */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.util.Pair<java.lang.String, com.google.android.exoplayer2.drm.DrmInitData.SchemeData> m1904h(org.xmlpull.v1.XmlPullParser r14) {
        /*
            Method dump skipped, instructions count: 335
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2146c.m1904h(org.xmlpull.v1.XmlPullParser):android.util.Pair");
    }

    /* renamed from: i */
    public int m1905i(XmlPullParser xmlPullParser) {
        String attributeValue = xmlPullParser.getAttributeValue(null, "contentType");
        if (TextUtils.isEmpty(attributeValue)) {
            return -1;
        }
        if ("audio".equals(attributeValue)) {
            return 1;
        }
        if ("video".equals(attributeValue)) {
            return 2;
        }
        return "text".equals(attributeValue) ? 3 : -1;
    }

    /* renamed from: j */
    public int m1906j(@Nullable String str) {
        if (str == null) {
            return 0;
        }
        switch (str) {
        }
        return 0;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:118:0x0b4c A[LOOP:3: B:109:0x0297->B:118:0x0b4c, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:119:0x09be A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:225:0x08c2 A[LOOP:7: B:215:0x0456->B:225:0x08c2, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:226:0x05d5 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:234:0x0653  */
    /* JADX WARN: Removed duplicated region for block: B:243:0x0683  */
    /* JADX WARN: Removed duplicated region for block: B:253:0x06a9  */
    /* JADX WARN: Removed duplicated region for block: B:300:0x0743  */
    /* JADX WARN: Removed duplicated region for block: B:325:0x086f  */
    /* JADX WARN: Removed duplicated region for block: B:328:0x0895  */
    /* JADX WARN: Removed duplicated region for block: B:340:0x0872  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0e62  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0e79  */
    /* JADX WARN: Removed duplicated region for block: B:390:0x0676 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0e07 A[LOOP:2: B:83:0x01a0->B:89:0x0e07, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0da2 A[SYNTHETIC] */
    /* renamed from: p */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2145b m1907p(org.xmlpull.v1.XmlPullParser r157, java.lang.String r158) {
        /*
            Method dump skipped, instructions count: 3774
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2146c.m1907p(org.xmlpull.v1.XmlPullParser, java.lang.String):b.l.a.a.k1.l0.k.b");
    }

    /* renamed from: q */
    public C2151h m1908q(XmlPullParser xmlPullParser, String str, String str2) {
        long j2;
        long j3;
        String attributeValue = xmlPullParser.getAttributeValue(null, str);
        String attributeValue2 = xmlPullParser.getAttributeValue(null, str2);
        if (attributeValue2 != null) {
            String[] split = attributeValue2.split("-");
            j2 = Long.parseLong(split[0]);
            if (split.length == 2) {
                j3 = (Long.parseLong(split[1]) - j2) + 1;
                return new C2151h(attributeValue, j2, j3);
            }
        } else {
            j2 = 0;
        }
        j3 = -1;
        return new C2151h(attributeValue, j2, j3);
    }

    /* renamed from: r */
    public AbstractC2153j.e m1909r(XmlPullParser xmlPullParser, @Nullable AbstractC2153j.e eVar) {
        long j2;
        long j3;
        long m1898o = m1898o(xmlPullParser, "timescale", eVar != null ? eVar.f4833b : 1L);
        long m1898o2 = m1898o(xmlPullParser, "presentationTimeOffset", eVar != null ? eVar.f4834c : 0L);
        long j4 = eVar != null ? eVar.f4844d : 0L;
        long j5 = eVar != null ? eVar.f4845e : 0L;
        String attributeValue = xmlPullParser.getAttributeValue(null, "indexRange");
        if (attributeValue != null) {
            String[] split = attributeValue.split("-");
            long parseLong = Long.parseLong(split[0]);
            j2 = (Long.parseLong(split[1]) - parseLong) + 1;
            j3 = parseLong;
        } else {
            j2 = j5;
            j3 = j4;
        }
        C2151h c2151h = eVar != null ? eVar.f4832a : null;
        do {
            xmlPullParser.next();
            if (C2354n.m2423Q0(xmlPullParser, "Initialization")) {
                c2151h = m1908q(xmlPullParser, "sourceURL", "range");
            } else {
                m1892d(xmlPullParser);
            }
        } while (!C2354n.m2408L0(xmlPullParser, "SegmentBase"));
        return new AbstractC2153j.e(c2151h, m1898o, m1898o2, j3, j2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: s */
    public AbstractC2153j.b m1910s(XmlPullParser xmlPullParser, @Nullable AbstractC2153j.b bVar, long j2) {
        C2151h c2151h;
        List list;
        List<AbstractC2153j.d> list2;
        long m1898o = m1898o(xmlPullParser, "timescale", bVar != null ? bVar.f4833b : 1L);
        long m1898o2 = m1898o(xmlPullParser, "presentationTimeOffset", bVar != null ? bVar.f4834c : 0L);
        long m1898o3 = m1898o(xmlPullParser, "duration", bVar != null ? bVar.f4836e : -9223372036854775807L);
        long m1898o4 = m1898o(xmlPullParser, "startNumber", bVar != null ? bVar.f4835d : 1L);
        List<AbstractC2153j.d> list3 = null;
        List list4 = null;
        C2151h c2151h2 = null;
        do {
            xmlPullParser.next();
            if (C2354n.m2423Q0(xmlPullParser, "Initialization")) {
                c2151h2 = m1908q(xmlPullParser, "sourceURL", "range");
            } else if (C2354n.m2423Q0(xmlPullParser, "SegmentTimeline")) {
                list3 = m1912u(xmlPullParser, m1898o, j2);
            } else if (C2354n.m2423Q0(xmlPullParser, "SegmentURL")) {
                if (list4 == null) {
                    list4 = new ArrayList();
                }
                List list5 = list4;
                list5.add(m1908q(xmlPullParser, "media", "mediaRange"));
                list4 = list5;
            } else {
                m1892d(xmlPullParser);
            }
        } while (!C2354n.m2408L0(xmlPullParser, "SegmentList"));
        if (bVar != null) {
            if (c2151h2 == null) {
                c2151h2 = bVar.f4832a;
            }
            if (list3 == null) {
                list3 = bVar.f4837f;
            }
            if (list4 == null) {
                list2 = list3;
                c2151h = c2151h2;
                list = bVar.f4838g;
                return new AbstractC2153j.b(c2151h, m1898o, m1898o2, m1898o4, m1898o3, list2, list);
            }
        }
        c2151h = c2151h2;
        list = list4;
        list2 = list3;
        return new AbstractC2153j.b(c2151h, m1898o, m1898o2, m1898o4, m1898o3, list2, list);
    }

    /* renamed from: t */
    public AbstractC2153j.c m1911t(XmlPullParser xmlPullParser, @Nullable AbstractC2153j.c cVar, List<C2147d> list, long j2) {
        long j3;
        long m1898o = m1898o(xmlPullParser, "timescale", cVar != null ? cVar.f4833b : 1L);
        long m1898o2 = m1898o(xmlPullParser, "presentationTimeOffset", cVar != null ? cVar.f4834c : 0L);
        long m1898o3 = m1898o(xmlPullParser, "duration", cVar != null ? cVar.f4836e : -9223372036854775807L);
        long m1898o4 = m1898o(xmlPullParser, "startNumber", cVar != null ? cVar.f4835d : 1L);
        int i2 = 0;
        while (true) {
            if (i2 >= list.size()) {
                j3 = -1;
                break;
            }
            C2147d c2147d = list.get(i2);
            if ("http://dashif.org/guidelines/last-segment-number".equalsIgnoreCase(c2147d.f4803a)) {
                j3 = Long.parseLong(c2147d.f4804b);
                break;
            }
            i2++;
        }
        long j4 = j3;
        List<AbstractC2153j.d> list2 = null;
        C2155l m1913w = m1913w(xmlPullParser, "media", cVar != null ? cVar.f4840h : null);
        C2155l m1913w2 = m1913w(xmlPullParser, "initialization", cVar != null ? cVar.f4839g : null);
        C2151h c2151h = null;
        do {
            xmlPullParser.next();
            if (C2354n.m2423Q0(xmlPullParser, "Initialization")) {
                c2151h = m1908q(xmlPullParser, "sourceURL", "range");
            } else if (C2354n.m2423Q0(xmlPullParser, "SegmentTimeline")) {
                list2 = m1912u(xmlPullParser, m1898o, j2);
            } else {
                m1892d(xmlPullParser);
            }
        } while (!C2354n.m2408L0(xmlPullParser, "SegmentTemplate"));
        if (cVar != null) {
            if (c2151h == null) {
                c2151h = cVar.f4832a;
            }
            if (list2 == null) {
                list2 = cVar.f4837f;
            }
        }
        return new AbstractC2153j.c(c2151h, m1898o, m1898o2, m1898o4, j4, m1898o3, list2, m1913w2, m1913w);
    }

    /* renamed from: u */
    public List<AbstractC2153j.d> m1912u(XmlPullParser xmlPullParser, long j2, long j3) {
        ArrayList arrayList = new ArrayList();
        long j4 = 0;
        long j5 = -9223372036854775807L;
        boolean z = false;
        int i2 = 0;
        do {
            xmlPullParser.next();
            if (C2354n.m2423Q0(xmlPullParser, ExifInterface.LATITUDE_SOUTH)) {
                long m1898o = m1898o(xmlPullParser, "t", -9223372036854775807L);
                if (z) {
                    j4 = m1901b(arrayList, j4, j5, i2, m1898o);
                }
                if (m1898o == -9223372036854775807L) {
                    m1898o = j4;
                }
                j5 = m1898o(xmlPullParser, "d", -9223372036854775807L);
                i2 = m1897n(xmlPullParser, "r", 0);
                j4 = m1898o;
                z = true;
            } else {
                m1892d(xmlPullParser);
            }
        } while (!C2354n.m2408L0(xmlPullParser, "SegmentTimeline"));
        if (z) {
            m1901b(arrayList, j4, j5, i2, C2344d0.m2314F(j3, j2, 1000L));
        }
        return arrayList;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00e2, code lost:
    
        switch(r9) {
            case 0: goto L47;
            case 1: goto L46;
            case 2: goto L45;
            default: goto L59;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00f1, code lost:
    
        r0[r5] = 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00fa, code lost:
    
        r1[r5] = r8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00f5, code lost:
    
        r0[r5] = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x00f8, code lost:
    
        r0[r5] = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00f0, code lost:
    
        throw new java.lang.IllegalArgumentException(p005b.p131d.p132a.p133a.C1499a.m637w("Invalid template: ", r12));
     */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    @androidx.annotation.Nullable
    /* renamed from: w */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2155l m1913w(org.xmlpull.v1.XmlPullParser r12, java.lang.String r13, @androidx.annotation.Nullable p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2155l r14) {
        /*
            Method dump skipped, instructions count: 292
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2146c.m1913w(org.xmlpull.v1.XmlPullParser, java.lang.String, b.l.a.a.k1.l0.k.l):b.l.a.a.k1.l0.k.l");
    }
}
