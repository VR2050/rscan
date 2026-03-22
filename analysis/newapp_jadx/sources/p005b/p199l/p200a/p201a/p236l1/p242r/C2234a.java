package p005b.p199l.p200a.p201a.p236l1.p242r;

import android.text.Layout;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2208c;
import p005b.p199l.p200a.p201a.p236l1.C2212g;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2348h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.r.a */
/* loaded from: classes.dex */
public final class C2234a extends AbstractC2208c {

    /* renamed from: n */
    public static final Pattern f5492n = Pattern.compile("^([0-9][0-9]+):([0-9][0-9]):([0-9][0-9])(?:(\\.[0-9]+)|:([0-9][0-9])(?:\\.([0-9]+))?)?$");

    /* renamed from: o */
    public static final Pattern f5493o = Pattern.compile("^([0-9]+(?:\\.[0-9]+)?)(h|m|s|ms|f|t)$");

    /* renamed from: p */
    public static final Pattern f5494p = Pattern.compile("^(([0-9]*.)?[0-9]+)(px|em|%)$");

    /* renamed from: q */
    public static final Pattern f5495q = Pattern.compile("^(\\d+\\.?\\d*?)% (\\d+\\.?\\d*?)%$");

    /* renamed from: r */
    public static final Pattern f5496r = Pattern.compile("^(\\d+\\.?\\d*?)px (\\d+\\.?\\d*?)px$");

    /* renamed from: s */
    public static final Pattern f5497s = Pattern.compile("^(\\d+) (\\d+)$");

    /* renamed from: t */
    public static final b f5498t = new b(30.0f, 1, 1);

    /* renamed from: u */
    public static final a f5499u = new a(32, 15);

    /* renamed from: v */
    public final XmlPullParserFactory f5500v;

    /* renamed from: b.l.a.a.l1.r.a$a */
    public static final class a {

        /* renamed from: a */
        public final int f5501a;

        public a(int i2, int i3) {
            this.f5501a = i3;
        }
    }

    /* renamed from: b.l.a.a.l1.r.a$b */
    public static final class b {

        /* renamed from: a */
        public final float f5502a;

        /* renamed from: b */
        public final int f5503b;

        /* renamed from: c */
        public final int f5504c;

        public b(float f2, int i2, int i3) {
            this.f5502a = f2;
            this.f5503b = i2;
            this.f5504c = i3;
        }
    }

    /* renamed from: b.l.a.a.l1.r.a$c */
    public static final class c {

        /* renamed from: a */
        public final int f5505a;

        /* renamed from: b */
        public final int f5506b;

        public c(int i2, int i3) {
            this.f5505a = i2;
            this.f5506b = i3;
        }
    }

    public C2234a() {
        super("TtmlDecoder");
        try {
            XmlPullParserFactory newInstance = XmlPullParserFactory.newInstance();
            this.f5500v = newInstance;
            newInstance.setNamespaceAware(true);
        } catch (XmlPullParserException e2) {
            throw new RuntimeException("Couldn't create XmlPullParserFactory instance", e2);
        }
    }

    /* renamed from: l */
    public static boolean m2098l(String str) {
        return str.equals("tt") || str.equals(BloggerOrderBean.order_recommend) || str.equals("body") || str.equals("div") || str.equals("p") || str.equals("span") || str.equals("br") || str.equals("style") || str.equals("styling") || str.equals("layout") || str.equals("region") || str.equals("metadata") || str.equals("image") || str.equals("data") || str.equals("information");
    }

    /* renamed from: n */
    public static void m2099n(String str, C2237d c2237d) {
        Matcher matcher;
        String group;
        int i2 = C2344d0.f6035a;
        String[] split = str.split("\\s+", -1);
        if (split.length == 1) {
            matcher = f5494p.matcher(str);
        } else {
            if (split.length != 2) {
                throw new C2212g(C1499a.m580B(C1499a.m586H("Invalid number of entries for fontSize: "), split.length, "."));
            }
            matcher = f5494p.matcher(split[1]);
        }
        if (!matcher.matches()) {
            throw new C2212g(C1499a.m639y("Invalid expression for fontSize: '", str, "'."));
        }
        group = matcher.group(3);
        group.hashCode();
        group.hashCode();
        switch (group) {
            case "%":
                c2237d.f5537j = 3;
                break;
            case "em":
                c2237d.f5537j = 2;
                break;
            case "px":
                c2237d.f5537j = 1;
                break;
            default:
                throw new C2212g(C1499a.m639y("Invalid unit for fontSize: '", group, "'."));
        }
        c2237d.f5538k = Float.valueOf(matcher.group(1)).floatValue();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x009f, code lost:
    
        if (r13.equals("ms") == false) goto L42;
     */
    /* JADX WARN: Failed to find 'out' block for switch in B:24:0x00cf. Please report as an issue. */
    /* renamed from: t */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static long m2100t(java.lang.String r13, p005b.p199l.p200a.p201a.p236l1.p242r.C2234a.b r14) {
        /*
            Method dump skipped, instructions count: 286
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p236l1.p242r.C2234a.m2100t(java.lang.String, b.l.a.a.l1.r.a$b):long");
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.AbstractC2208c
    /* renamed from: j */
    public InterfaceC2210e mo2047j(byte[] bArr, int i2, boolean z) {
        b bVar;
        try {
            XmlPullParser newPullParser = this.f5500v.newPullParser();
            Map<String, C2237d> hashMap = new HashMap<>();
            HashMap hashMap2 = new HashMap();
            Map<String, String> hashMap3 = new HashMap<>();
            hashMap2.put("", new C2236c(null, -3.4028235E38f, -3.4028235E38f, Integer.MIN_VALUE, Integer.MIN_VALUE, -3.4028235E38f, -3.4028235E38f, Integer.MIN_VALUE, -3.4028235E38f));
            c cVar = null;
            newPullParser.setInput(new ByteArrayInputStream(bArr, 0, i2), null);
            ArrayDeque arrayDeque = new ArrayDeque();
            b bVar2 = f5498t;
            a aVar = f5499u;
            C2238e c2238e = null;
            int i3 = 0;
            for (int eventType = newPullParser.getEventType(); eventType != 1; eventType = newPullParser.getEventType()) {
                C2235b c2235b = (C2235b) arrayDeque.peek();
                if (i3 == 0) {
                    String name = newPullParser.getName();
                    if (eventType == 2) {
                        if ("tt".equals(name)) {
                            bVar2 = m2103o(newPullParser);
                            aVar = m2102m(newPullParser, f5499u);
                            cVar = m2108u(newPullParser);
                        }
                        c cVar2 = cVar;
                        b bVar3 = bVar2;
                        a aVar2 = aVar;
                        if (!m2098l(name)) {
                            newPullParser.getName();
                            i3++;
                            bVar = bVar3;
                        } else if (BloggerOrderBean.order_recommend.equals(name)) {
                            bVar = bVar3;
                            m2104p(newPullParser, hashMap, aVar2, cVar2, hashMap2, hashMap3);
                        } else {
                            bVar = bVar3;
                            try {
                                C2235b m2105q = m2105q(newPullParser, c2235b, hashMap2, bVar);
                                arrayDeque.push(m2105q);
                                if (c2235b != null) {
                                    c2235b.m2111a(m2105q);
                                }
                            } catch (C2212g unused) {
                                i3++;
                            }
                        }
                        bVar2 = bVar;
                        cVar = cVar2;
                        aVar = aVar2;
                    } else if (eventType == 4) {
                        C2235b m2109b = C2235b.m2109b(newPullParser.getText());
                        if (c2235b.f5518l == null) {
                            c2235b.f5518l = new ArrayList();
                        }
                        c2235b.f5518l.add(m2109b);
                    } else if (eventType == 3) {
                        if (newPullParser.getName().equals("tt")) {
                            c2238e = new C2238e((C2235b) arrayDeque.peek(), hashMap, hashMap2, hashMap3);
                        }
                        arrayDeque.pop();
                    }
                } else if (eventType == 2) {
                    i3++;
                } else if (eventType == 3) {
                    i3--;
                }
                newPullParser.next();
            }
            return c2238e;
        } catch (IOException e2) {
            throw new IllegalStateException("Unexpected error when reading input.", e2);
        } catch (XmlPullParserException e3) {
            throw new C2212g("Unable to decode source", e3);
        }
    }

    /* renamed from: k */
    public final C2237d m2101k(C2237d c2237d) {
        return c2237d == null ? new C2237d() : c2237d;
    }

    /* renamed from: m */
    public final a m2102m(XmlPullParser xmlPullParser, a aVar) {
        String attributeValue = xmlPullParser.getAttributeValue("http://www.w3.org/ns/ttml#parameter", "cellResolution");
        if (attributeValue == null) {
            return aVar;
        }
        Matcher matcher = f5497s.matcher(attributeValue);
        if (!matcher.matches()) {
            return aVar;
        }
        try {
            int parseInt = Integer.parseInt(matcher.group(1));
            int parseInt2 = Integer.parseInt(matcher.group(2));
            if (parseInt != 0 && parseInt2 != 0) {
                return new a(parseInt, parseInt2);
            }
            throw new C2212g("Invalid cell resolution " + parseInt + " " + parseInt2);
        } catch (NumberFormatException unused) {
            return aVar;
        }
    }

    /* renamed from: o */
    public final b m2103o(XmlPullParser xmlPullParser) {
        String attributeValue = xmlPullParser.getAttributeValue("http://www.w3.org/ns/ttml#parameter", "frameRate");
        int parseInt = attributeValue != null ? Integer.parseInt(attributeValue) : 30;
        float f2 = 1.0f;
        String attributeValue2 = xmlPullParser.getAttributeValue("http://www.w3.org/ns/ttml#parameter", "frameRateMultiplier");
        if (attributeValue2 != null) {
            int i2 = C2344d0.f6035a;
            if (attributeValue2.split(" ", -1).length != 2) {
                throw new C2212g("frameRateMultiplier doesn't have 2 parts");
            }
            f2 = Integer.parseInt(r2[0]) / Integer.parseInt(r2[1]);
        }
        b bVar = f5498t;
        int i3 = bVar.f5503b;
        String attributeValue3 = xmlPullParser.getAttributeValue("http://www.w3.org/ns/ttml#parameter", "subFrameRate");
        if (attributeValue3 != null) {
            i3 = Integer.parseInt(attributeValue3);
        }
        int i4 = bVar.f5504c;
        String attributeValue4 = xmlPullParser.getAttributeValue("http://www.w3.org/ns/ttml#parameter", "tickRate");
        if (attributeValue4 != null) {
            i4 = Integer.parseInt(attributeValue4);
        }
        return new b(parseInt * f2, i3, i4);
    }

    /* renamed from: p */
    public final Map<String, C2237d> m2104p(XmlPullParser xmlPullParser, Map<String, C2237d> map, a aVar, c cVar, Map<String, C2236c> map2, Map<String, String> map3) {
        String m2483i0;
        String m2483i02;
        float parseFloat;
        float parseFloat2;
        float parseInt;
        float parseInt2;
        float f2;
        int i2;
        do {
            xmlPullParser.next();
            if (C2354n.m2423Q0(xmlPullParser, "style")) {
                String m2483i03 = C2354n.m2483i0(xmlPullParser, "style");
                C2237d m2106r = m2106r(xmlPullParser, new C2237d());
                if (m2483i03 != null) {
                    for (String str : m2107s(m2483i03)) {
                        m2106r.m2119a(map.get(str));
                    }
                }
                String str2 = m2106r.f5539l;
                if (str2 != null) {
                    map.put(str2, m2106r);
                }
            } else if (C2354n.m2423Q0(xmlPullParser, "region")) {
                String m2483i04 = C2354n.m2483i0(xmlPullParser, "id");
                C2236c c2236c = null;
                if (m2483i04 != null && (m2483i02 = C2354n.m2483i0(xmlPullParser, "origin")) != null) {
                    Pattern pattern = f5495q;
                    Matcher matcher = pattern.matcher(m2483i02);
                    Pattern pattern2 = f5496r;
                    Matcher matcher2 = pattern2.matcher(m2483i02);
                    if (matcher.matches()) {
                        try {
                            parseFloat = Float.parseFloat(matcher.group(1)) / 100.0f;
                            parseFloat2 = Float.parseFloat(matcher.group(2)) / 100.0f;
                        } catch (NumberFormatException unused) {
                        }
                    } else if (matcher2.matches() && cVar != null) {
                        float parseInt3 = Integer.parseInt(matcher2.group(1)) / cVar.f5505a;
                        parseFloat2 = Integer.parseInt(matcher2.group(2)) / cVar.f5506b;
                        parseFloat = parseInt3;
                    }
                    String m2483i05 = C2354n.m2483i0(xmlPullParser, "extent");
                    if (m2483i05 != null) {
                        Matcher matcher3 = pattern.matcher(m2483i05);
                        Matcher matcher4 = pattern2.matcher(m2483i05);
                        if (matcher3.matches()) {
                            float parseFloat3 = Float.parseFloat(matcher3.group(1)) / 100.0f;
                            parseInt2 = Float.parseFloat(matcher3.group(2)) / 100.0f;
                            parseInt = parseFloat3;
                        } else if (matcher4.matches() && cVar != null) {
                            parseInt = Integer.parseInt(matcher4.group(1)) / cVar.f5505a;
                            parseInt2 = Integer.parseInt(matcher4.group(2)) / cVar.f5506b;
                        }
                        String m2483i06 = C2354n.m2483i0(xmlPullParser, "displayAlign");
                        if (m2483i06 != null) {
                            String m2320L = C2344d0.m2320L(m2483i06);
                            m2320L.hashCode();
                            if (m2320L.equals("center")) {
                                f2 = (parseInt2 / 2.0f) + parseFloat2;
                                i2 = 1;
                            } else if (m2320L.equals("after")) {
                                f2 = parseFloat2 + parseInt2;
                                i2 = 2;
                            }
                            c2236c = new C2236c(m2483i04, parseFloat, f2, 0, i2, parseInt, parseInt2, 1, 1.0f / aVar.f5501a);
                        }
                        f2 = parseFloat2;
                        i2 = 0;
                        c2236c = new C2236c(m2483i04, parseFloat, f2, 0, i2, parseInt, parseInt2, 1, 1.0f / aVar.f5501a);
                    }
                }
                if (c2236c != null) {
                    map2.put(c2236c.f5519a, c2236c);
                }
            } else if (C2354n.m2423Q0(xmlPullParser, "metadata")) {
                do {
                    xmlPullParser.next();
                    if (C2354n.m2423Q0(xmlPullParser, "image") && (m2483i0 = C2354n.m2483i0(xmlPullParser, "id")) != null) {
                        map3.put(m2483i0, xmlPullParser.nextText());
                    }
                } while (!C2354n.m2408L0(xmlPullParser, "metadata"));
            }
        } while (!C2354n.m2408L0(xmlPullParser, BloggerOrderBean.order_recommend));
        return map;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* renamed from: q */
    public final C2235b m2105q(XmlPullParser xmlPullParser, C2235b c2235b, Map<String, C2236c> map, b bVar) {
        long j2;
        char c2;
        XmlPullParser xmlPullParser2 = xmlPullParser;
        int attributeCount = xmlPullParser.getAttributeCount();
        C2237d m2106r = m2106r(xmlPullParser2, null);
        String[] strArr = null;
        String str = null;
        String str2 = "";
        int i2 = 0;
        long j3 = -9223372036854775807L;
        long j4 = -9223372036854775807L;
        long j5 = -9223372036854775807L;
        while (i2 < attributeCount) {
            String attributeName = xmlPullParser2.getAttributeName(i2);
            String attributeValue = xmlPullParser2.getAttributeValue(i2);
            attributeName.hashCode();
            switch (attributeName.hashCode()) {
                case -934795532:
                    if (attributeName.equals("region")) {
                        c2 = 0;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 99841:
                    if (attributeName.equals("dur")) {
                        c2 = 1;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 100571:
                    if (attributeName.equals("end")) {
                        c2 = 2;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 93616297:
                    if (attributeName.equals("begin")) {
                        c2 = 3;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 109780401:
                    if (attributeName.equals("style")) {
                        c2 = 4;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 1292595405:
                    if (attributeName.equals("backgroundImage")) {
                        c2 = 5;
                        break;
                    }
                    c2 = 65535;
                    break;
                default:
                    c2 = 65535;
                    break;
            }
            if (c2 != 0) {
                if (c2 == 1) {
                    j5 = m2100t(attributeValue, bVar);
                } else if (c2 == 2) {
                    j4 = m2100t(attributeValue, bVar);
                } else if (c2 == 3) {
                    j3 = m2100t(attributeValue, bVar);
                } else if (c2 == 4) {
                    String[] m2107s = m2107s(attributeValue);
                    if (m2107s.length > 0) {
                        strArr = m2107s;
                    }
                } else if (c2 == 5 && attributeValue.startsWith("#")) {
                    str = attributeValue.substring(1);
                }
            } else if (map.containsKey(attributeValue)) {
                str2 = attributeValue;
            }
            i2++;
            xmlPullParser2 = xmlPullParser;
        }
        if (c2235b != null) {
            long j6 = c2235b.f5510d;
            j2 = -9223372036854775807L;
            if (j6 != -9223372036854775807L) {
                if (j3 != -9223372036854775807L) {
                    j3 += j6;
                }
                if (j4 != -9223372036854775807L) {
                    j4 += j6;
                }
            }
        } else {
            j2 = -9223372036854775807L;
        }
        if (j4 == j2) {
            if (j5 != j2) {
                j4 = j3 + j5;
            } else if (c2235b != null) {
                long j7 = c2235b.f5511e;
                if (j7 != j2) {
                    j4 = j7;
                }
            }
        }
        return new C2235b(xmlPullParser.getName(), null, j3, j4, m2106r, strArr, str2, str);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* renamed from: r */
    public final C2237d m2106r(XmlPullParser xmlPullParser, C2237d c2237d) {
        char c2;
        int attributeCount = xmlPullParser.getAttributeCount();
        for (int i2 = 0; i2 < attributeCount; i2++) {
            String attributeValue = xmlPullParser.getAttributeValue(i2);
            String attributeName = xmlPullParser.getAttributeName(i2);
            attributeName.hashCode();
            char c3 = 65535;
            switch (attributeName.hashCode()) {
                case -1550943582:
                    if (attributeName.equals("fontStyle")) {
                        c2 = 0;
                        break;
                    }
                    c2 = 65535;
                    break;
                case -1224696685:
                    if (attributeName.equals("fontFamily")) {
                        c2 = 1;
                        break;
                    }
                    c2 = 65535;
                    break;
                case -1065511464:
                    if (attributeName.equals("textAlign")) {
                        c2 = 2;
                        break;
                    }
                    c2 = 65535;
                    break;
                case -879295043:
                    if (attributeName.equals("textDecoration")) {
                        c2 = 3;
                        break;
                    }
                    c2 = 65535;
                    break;
                case -734428249:
                    if (attributeName.equals("fontWeight")) {
                        c2 = 4;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 3355:
                    if (attributeName.equals("id")) {
                        c2 = 5;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 94842723:
                    if (attributeName.equals("color")) {
                        c2 = 6;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 365601008:
                    if (attributeName.equals("fontSize")) {
                        c2 = 7;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 1287124693:
                    if (attributeName.equals("backgroundColor")) {
                        c2 = '\b';
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
                    c2237d = m2101k(c2237d);
                    boolean equalsIgnoreCase = "italic".equalsIgnoreCase(attributeValue);
                    C4195m.m4771I(true);
                    c2237d.f5536i = equalsIgnoreCase ? 1 : 0;
                    break;
                case 1:
                    c2237d = m2101k(c2237d);
                    C4195m.m4771I(true);
                    c2237d.f5528a = attributeValue;
                    break;
                case 2:
                    String m2320L = C2344d0.m2320L(attributeValue);
                    m2320L.hashCode();
                    switch (m2320L.hashCode()) {
                        case -1364013995:
                            if (m2320L.equals("center")) {
                                c3 = 0;
                                break;
                            }
                            break;
                        case 100571:
                            if (m2320L.equals("end")) {
                                c3 = 1;
                                break;
                            }
                            break;
                        case 3317767:
                            if (m2320L.equals("left")) {
                                c3 = 2;
                                break;
                            }
                            break;
                        case 108511772:
                            if (m2320L.equals("right")) {
                                c3 = 3;
                                break;
                            }
                            break;
                        case 109757538:
                            if (m2320L.equals("start")) {
                                c3 = 4;
                                break;
                            }
                            break;
                    }
                    if (c3 != 0) {
                        if (c3 != 1) {
                            if (c3 != 2) {
                                if (c3 != 3) {
                                    if (c3 != 4) {
                                        break;
                                    } else {
                                        c2237d = m2101k(c2237d);
                                        c2237d.f5540m = Layout.Alignment.ALIGN_NORMAL;
                                        break;
                                    }
                                } else {
                                    c2237d = m2101k(c2237d);
                                    c2237d.f5540m = Layout.Alignment.ALIGN_OPPOSITE;
                                    break;
                                }
                            } else {
                                c2237d = m2101k(c2237d);
                                c2237d.f5540m = Layout.Alignment.ALIGN_NORMAL;
                                break;
                            }
                        } else {
                            c2237d = m2101k(c2237d);
                            c2237d.f5540m = Layout.Alignment.ALIGN_OPPOSITE;
                            break;
                        }
                    } else {
                        c2237d = m2101k(c2237d);
                        c2237d.f5540m = Layout.Alignment.ALIGN_CENTER;
                        break;
                    }
                case 3:
                    String m2320L2 = C2344d0.m2320L(attributeValue);
                    m2320L2.hashCode();
                    switch (m2320L2.hashCode()) {
                        case -1461280213:
                            if (m2320L2.equals("nounderline")) {
                                c3 = 0;
                                break;
                            }
                            break;
                        case -1026963764:
                            if (m2320L2.equals("underline")) {
                                c3 = 1;
                                break;
                            }
                            break;
                        case 913457136:
                            if (m2320L2.equals("nolinethrough")) {
                                c3 = 2;
                                break;
                            }
                            break;
                        case 1679736913:
                            if (m2320L2.equals("linethrough")) {
                                c3 = 3;
                                break;
                            }
                            break;
                    }
                    if (c3 != 0) {
                        if (c3 != 1) {
                            if (c3 != 2) {
                                if (c3 != 3) {
                                    break;
                                } else {
                                    c2237d = m2101k(c2237d);
                                    C4195m.m4771I(true);
                                    c2237d.f5533f = 1;
                                    break;
                                }
                            } else {
                                c2237d = m2101k(c2237d);
                                C4195m.m4771I(true);
                                c2237d.f5533f = 0;
                                break;
                            }
                        } else {
                            c2237d = m2101k(c2237d);
                            C4195m.m4771I(true);
                            c2237d.f5534g = 1;
                            break;
                        }
                    } else {
                        c2237d = m2101k(c2237d);
                        C4195m.m4771I(true);
                        c2237d.f5534g = 0;
                        break;
                    }
                case 4:
                    c2237d = m2101k(c2237d);
                    boolean equalsIgnoreCase2 = "bold".equalsIgnoreCase(attributeValue);
                    C4195m.m4771I(true);
                    c2237d.f5535h = equalsIgnoreCase2 ? 1 : 0;
                    break;
                case 5:
                    if ("style".equals(xmlPullParser.getName())) {
                        c2237d = m2101k(c2237d);
                        c2237d.f5539l = attributeValue;
                        break;
                    } else {
                        break;
                    }
                case 6:
                    c2237d = m2101k(c2237d);
                    int m2360a = C2348h.m2360a(attributeValue, false);
                    C4195m.m4771I(true);
                    c2237d.f5529b = m2360a;
                    c2237d.f5530c = true;
                    break;
                case 7:
                    c2237d = m2101k(c2237d);
                    m2099n(attributeValue, c2237d);
                    break;
                case '\b':
                    c2237d = m2101k(c2237d);
                    try {
                        c2237d.f5531d = C2348h.m2360a(attributeValue, false);
                        c2237d.f5532e = true;
                        break;
                    } catch (C2212g | IllegalArgumentException unused) {
                        break;
                    }
            }
        }
        return c2237d;
    }

    /* renamed from: s */
    public final String[] m2107s(String str) {
        String trim = str.trim();
        if (trim.isEmpty()) {
            return new String[0];
        }
        int i2 = C2344d0.f6035a;
        return trim.split("\\s+", -1);
    }

    /* renamed from: u */
    public final c m2108u(XmlPullParser xmlPullParser) {
        String m2483i0 = C2354n.m2483i0(xmlPullParser, "extent");
        if (m2483i0 == null) {
            return null;
        }
        Matcher matcher = f5496r.matcher(m2483i0);
        if (!matcher.matches()) {
            return null;
        }
        try {
            return new c(Integer.parseInt(matcher.group(1)), Integer.parseInt(matcher.group(2)));
        } catch (NumberFormatException unused) {
            return null;
        }
    }
}
