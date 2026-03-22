package p005b.p199l.p200a.p201a.p227k1.p234n0.p235e;

import android.net.Uri;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Pair;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1990j;
import p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2190a;
import p005b.p199l.p200a.p201a.p248o1.C2285c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2347g;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.n0.e.b */
/* loaded from: classes.dex */
public class C2191b implements C2285c0.a<C2190a> {

    /* renamed from: a */
    public final XmlPullParserFactory f5182a;

    /* renamed from: b.l.a.a.k1.n0.e.b$a */
    public static abstract class a {

        /* renamed from: a */
        public final String f5183a;

        /* renamed from: b */
        public final String f5184b;

        /* renamed from: c */
        @Nullable
        public final a f5185c;

        /* renamed from: d */
        public final List<Pair<String, Object>> f5186d = new LinkedList();

        public a(@Nullable a aVar, String str, String str2) {
            this.f5185c = aVar;
            this.f5183a = str;
            this.f5184b = str2;
        }

        /* renamed from: a */
        public void mo2007a(Object obj) {
        }

        /* renamed from: b */
        public abstract Object mo2008b();

        @Nullable
        /* renamed from: c */
        public final Object m2009c(String str) {
            for (int i2 = 0; i2 < this.f5186d.size(); i2++) {
                Pair<String, Object> pair = this.f5186d.get(i2);
                if (((String) pair.first).equals(str)) {
                    return pair.second;
                }
            }
            a aVar = this.f5185c;
            if (aVar == null) {
                return null;
            }
            return aVar.m2009c(str);
        }

        /* renamed from: d */
        public boolean mo2010d(String str) {
            return false;
        }

        /* renamed from: e */
        public final Object m2011e(XmlPullParser xmlPullParser) {
            boolean z = false;
            int i2 = 0;
            while (true) {
                int eventType = xmlPullParser.getEventType();
                a aVar = null;
                if (eventType == 1) {
                    return null;
                }
                if (eventType == 2) {
                    String name = xmlPullParser.getName();
                    if (this.f5184b.equals(name)) {
                        mo2017k(xmlPullParser);
                        z = true;
                    } else if (z) {
                        if (i2 > 0) {
                            i2++;
                        } else if (mo2010d(name)) {
                            mo2017k(xmlPullParser);
                        } else {
                            String str = this.f5183a;
                            if ("QualityLevel".equals(name)) {
                                aVar = new d(this, str);
                            } else if ("Protection".equals(name)) {
                                aVar = new c(this, str);
                            } else if ("StreamIndex".equals(name)) {
                                aVar = new f(this, str);
                            }
                            if (aVar == null) {
                                i2 = 1;
                            } else {
                                mo2007a(aVar.m2011e(xmlPullParser));
                            }
                        }
                    }
                } else if (eventType != 3) {
                    if (eventType == 4 && z && i2 == 0) {
                        mo2018l(xmlPullParser);
                    }
                } else if (!z) {
                    continue;
                } else if (i2 > 0) {
                    i2--;
                } else {
                    String name2 = xmlPullParser.getName();
                    mo2012f(xmlPullParser);
                    if (!mo2010d(name2)) {
                        return mo2008b();
                    }
                }
                xmlPullParser.next();
            }
        }

        /* renamed from: f */
        public void mo2012f(XmlPullParser xmlPullParser) {
        }

        /* renamed from: g */
        public final int m2013g(XmlPullParser xmlPullParser, String str, int i2) {
            String attributeValue = xmlPullParser.getAttributeValue(null, str);
            if (attributeValue == null) {
                return i2;
            }
            try {
                return Integer.parseInt(attributeValue);
            } catch (NumberFormatException e2) {
                throw new C2205l0(e2);
            }
        }

        /* renamed from: h */
        public final long m2014h(XmlPullParser xmlPullParser, String str, long j2) {
            String attributeValue = xmlPullParser.getAttributeValue(null, str);
            if (attributeValue == null) {
                return j2;
            }
            try {
                return Long.parseLong(attributeValue);
            } catch (NumberFormatException e2) {
                throw new C2205l0(e2);
            }
        }

        /* renamed from: i */
        public final int m2015i(XmlPullParser xmlPullParser, String str) {
            String attributeValue = xmlPullParser.getAttributeValue(null, str);
            if (attributeValue == null) {
                throw new b(str);
            }
            try {
                return Integer.parseInt(attributeValue);
            } catch (NumberFormatException e2) {
                throw new C2205l0(e2);
            }
        }

        /* renamed from: j */
        public final String m2016j(XmlPullParser xmlPullParser, String str) {
            String attributeValue = xmlPullParser.getAttributeValue(null, str);
            if (attributeValue != null) {
                return attributeValue;
            }
            throw new b(str);
        }

        /* renamed from: k */
        public abstract void mo2017k(XmlPullParser xmlPullParser);

        /* renamed from: l */
        public void mo2018l(XmlPullParser xmlPullParser) {
        }
    }

    /* renamed from: b.l.a.a.k1.n0.e.b$b */
    public static class b extends C2205l0 {
        public b(String str) {
            super(C1499a.m637w("Missing required field: ", str));
        }
    }

    /* renamed from: b.l.a.a.k1.n0.e.b$c */
    public static class c extends a {

        /* renamed from: e */
        public boolean f5187e;

        /* renamed from: f */
        public UUID f5188f;

        /* renamed from: g */
        public byte[] f5189g;

        public c(a aVar, String str) {
            super(aVar, str, "Protection");
        }

        /* renamed from: m */
        public static void m2019m(byte[] bArr, int i2, int i3) {
            byte b2 = bArr[i2];
            bArr[i2] = bArr[i3];
            bArr[i3] = b2;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: b */
        public Object mo2008b() {
            UUID uuid = this.f5188f;
            byte[] m4844z = C4195m.m4844z(uuid, this.f5189g);
            byte[] bArr = this.f5189g;
            C1990j[] c1990jArr = new C1990j[1];
            StringBuilder sb = new StringBuilder();
            for (int i2 = 0; i2 < bArr.length; i2 += 2) {
                sb.append((char) bArr[i2]);
            }
            String sb2 = sb.toString();
            byte[] decode = Base64.decode(sb2.substring(sb2.indexOf("<KID>") + 5, sb2.indexOf("</KID>")), 0);
            m2019m(decode, 0, 3);
            byte b2 = decode[1];
            decode[1] = decode[2];
            decode[2] = b2;
            byte b3 = decode[4];
            decode[4] = decode[5];
            decode[5] = b3;
            byte b4 = decode[6];
            decode[6] = decode[7];
            decode[7] = b4;
            c1990jArr[0] = new C1990j(true, null, 8, decode, 0, 0, null);
            return new C2190a.a(uuid, m4844z, c1990jArr);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: d */
        public boolean mo2010d(String str) {
            return "ProtectionHeader".equals(str);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: f */
        public void mo2012f(XmlPullParser xmlPullParser) {
            if ("ProtectionHeader".equals(xmlPullParser.getName())) {
                this.f5187e = false;
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: k */
        public void mo2017k(XmlPullParser xmlPullParser) {
            if ("ProtectionHeader".equals(xmlPullParser.getName())) {
                this.f5187e = true;
                String attributeValue = xmlPullParser.getAttributeValue(null, "SystemID");
                if (attributeValue.charAt(0) == '{' && attributeValue.charAt(attributeValue.length() - 1) == '}') {
                    attributeValue = attributeValue.substring(1, attributeValue.length() - 1);
                }
                this.f5188f = UUID.fromString(attributeValue);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: l */
        public void mo2018l(XmlPullParser xmlPullParser) {
            if (this.f5187e) {
                this.f5189g = Base64.decode(xmlPullParser.getText(), 0);
            }
        }
    }

    /* renamed from: b.l.a.a.k1.n0.e.b$d */
    public static class d extends a {

        /* renamed from: e */
        public Format f5190e;

        public d(a aVar, String str) {
            super(aVar, str, "QualityLevel");
        }

        /* renamed from: m */
        public static List<byte[]> m2020m(String str) {
            byte[][] bArr;
            ArrayList arrayList = new ArrayList();
            if (!TextUtils.isEmpty(str)) {
                int i2 = C2344d0.f6035a;
                int length = str.length() / 2;
                byte[] bArr2 = new byte[length];
                for (int i3 = 0; i3 < length; i3++) {
                    int i4 = i3 * 2;
                    bArr2[i3] = (byte) (Character.digit(str.charAt(i4 + 1), 16) + (Character.digit(str.charAt(i4), 16) << 4));
                }
                if (C2347g.m2357c(bArr2, 0)) {
                    ArrayList arrayList2 = new ArrayList();
                    int i5 = 0;
                    do {
                        arrayList2.add(Integer.valueOf(i5));
                        byte[] bArr3 = C2347g.f6054a;
                        i5 += bArr3.length;
                        int length2 = length - bArr3.length;
                        while (true) {
                            if (i5 > length2) {
                                i5 = -1;
                                break;
                            }
                            if (C2347g.m2357c(bArr2, i5)) {
                                break;
                            }
                            i5++;
                        }
                    } while (i5 != -1);
                    byte[][] bArr4 = new byte[arrayList2.size()][];
                    int i6 = 0;
                    while (i6 < arrayList2.size()) {
                        int intValue = ((Integer) arrayList2.get(i6)).intValue();
                        int intValue2 = (i6 < arrayList2.size() + (-1) ? ((Integer) arrayList2.get(i6 + 1)).intValue() : length) - intValue;
                        byte[] bArr5 = new byte[intValue2];
                        System.arraycopy(bArr2, intValue, bArr5, 0, intValue2);
                        bArr4[i6] = bArr5;
                        i6++;
                    }
                    bArr = bArr4;
                } else {
                    bArr = null;
                }
                if (bArr == null) {
                    arrayList.add(bArr2);
                } else {
                    Collections.addAll(arrayList, bArr);
                }
            }
            return arrayList;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: b */
        public Object mo2008b() {
            return this.f5190e;
        }

        /* JADX WARN: Removed duplicated region for block: B:35:0x00f0  */
        /* JADX WARN: Removed duplicated region for block: B:38:0x0117  */
        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: k */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void mo2017k(org.xmlpull.v1.XmlPullParser r19) {
            /*
                Method dump skipped, instructions count: 478
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.d.mo2017k(org.xmlpull.v1.XmlPullParser):void");
        }
    }

    /* renamed from: b.l.a.a.k1.n0.e.b$e */
    public static class e extends a {

        /* renamed from: e */
        public final List<C2190a.b> f5191e;

        /* renamed from: f */
        public int f5192f;

        /* renamed from: g */
        public int f5193g;

        /* renamed from: h */
        public long f5194h;

        /* renamed from: i */
        public long f5195i;

        /* renamed from: j */
        public long f5196j;

        /* renamed from: k */
        public int f5197k;

        /* renamed from: l */
        public boolean f5198l;

        /* renamed from: m */
        @Nullable
        public C2190a.a f5199m;

        public e(a aVar, String str) {
            super(null, str, "SmoothStreamingMedia");
            this.f5197k = -1;
            this.f5199m = null;
            this.f5191e = new LinkedList();
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: a */
        public void mo2007a(Object obj) {
            if (obj instanceof C2190a.b) {
                this.f5191e.add((C2190a.b) obj);
            } else if (obj instanceof C2190a.a) {
                C4195m.m4771I(this.f5199m == null);
                this.f5199m = (C2190a.a) obj;
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: b */
        public Object mo2008b() {
            int size = this.f5191e.size();
            C2190a.b[] bVarArr = new C2190a.b[size];
            this.f5191e.toArray(bVarArr);
            C2190a.a aVar = this.f5199m;
            if (aVar != null) {
                DrmInitData drmInitData = new DrmInitData(null, true, new DrmInitData.SchemeData(aVar.f5163a, null, "video/mp4", aVar.f5164b));
                for (int i2 = 0; i2 < size; i2++) {
                    C2190a.b bVar = bVarArr[i2];
                    int i3 = bVar.f5166a;
                    if (i3 == 2 || i3 == 1) {
                        Format[] formatArr = bVar.f5175j;
                        for (int i4 = 0; i4 < formatArr.length; i4++) {
                            Format format = formatArr[i4];
                            formatArr[i4] = format.m4042b(drmInitData, format.f9243j);
                        }
                    }
                }
            }
            return new C2190a(this.f5192f, this.f5193g, this.f5194h, this.f5195i, this.f5196j, this.f5197k, this.f5198l, this.f5199m, bVarArr);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: k */
        public void mo2017k(XmlPullParser xmlPullParser) {
            this.f5192f = m2015i(xmlPullParser, "MajorVersion");
            this.f5193g = m2015i(xmlPullParser, "MinorVersion");
            this.f5194h = m2014h(xmlPullParser, "TimeScale", 10000000L);
            String attributeValue = xmlPullParser.getAttributeValue(null, "Duration");
            if (attributeValue == null) {
                throw new b("Duration");
            }
            try {
                this.f5195i = Long.parseLong(attributeValue);
                this.f5196j = m2014h(xmlPullParser, "DVRWindowLength", 0L);
                this.f5197k = m2013g(xmlPullParser, "LookaheadCount", -1);
                String attributeValue2 = xmlPullParser.getAttributeValue(null, "IsLive");
                this.f5198l = attributeValue2 != null ? Boolean.parseBoolean(attributeValue2) : false;
                this.f5186d.add(Pair.create("TimeScale", Long.valueOf(this.f5194h)));
            } catch (NumberFormatException e2) {
                throw new C2205l0(e2);
            }
        }
    }

    /* renamed from: b.l.a.a.k1.n0.e.b$f */
    public static class f extends a {

        /* renamed from: e */
        public final String f5200e;

        /* renamed from: f */
        public final List<Format> f5201f;

        /* renamed from: g */
        public int f5202g;

        /* renamed from: h */
        public String f5203h;

        /* renamed from: i */
        public long f5204i;

        /* renamed from: j */
        public String f5205j;

        /* renamed from: k */
        public String f5206k;

        /* renamed from: l */
        public int f5207l;

        /* renamed from: m */
        public int f5208m;

        /* renamed from: n */
        public int f5209n;

        /* renamed from: o */
        public int f5210o;

        /* renamed from: p */
        public String f5211p;

        /* renamed from: q */
        public ArrayList<Long> f5212q;

        /* renamed from: r */
        public long f5213r;

        public f(a aVar, String str) {
            super(aVar, str, "StreamIndex");
            this.f5200e = str;
            this.f5201f = new LinkedList();
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: a */
        public void mo2007a(Object obj) {
            if (obj instanceof Format) {
                this.f5201f.add((Format) obj);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: b */
        public Object mo2008b() {
            String str;
            String str2;
            String str3;
            Format[] formatArr = new Format[this.f5201f.size()];
            this.f5201f.toArray(formatArr);
            String str4 = this.f5200e;
            String str5 = this.f5206k;
            int i2 = this.f5202g;
            String str6 = this.f5203h;
            long j2 = this.f5204i;
            String str7 = this.f5205j;
            int i3 = this.f5207l;
            int i4 = this.f5208m;
            int i5 = this.f5209n;
            int i6 = this.f5210o;
            String str8 = this.f5211p;
            ArrayList<Long> arrayList = this.f5212q;
            long j3 = this.f5213r;
            int i7 = C2344d0.f6035a;
            int size = arrayList.size();
            long[] jArr = new long[size];
            if (j2 < 1000000 || j2 % 1000000 != 0) {
                str = str7;
                if (j2 >= 1000000 || 1000000 % j2 != 0) {
                    str2 = str6;
                    str3 = str8;
                    double d2 = 1000000 / j2;
                    int i8 = 0;
                    while (i8 < size) {
                        jArr[i8] = (long) (arrayList.get(i8).longValue() * d2);
                        i8++;
                        arrayList = arrayList;
                    }
                    return new C2190a.b(str4, str5, i2, str2, j2, str, i3, i4, i5, i6, str3, formatArr, arrayList, jArr, C2344d0.m2314F(j3, 1000000L, j2));
                }
                long j4 = 1000000 / j2;
                for (int i9 = 0; i9 < size; i9++) {
                    jArr[i9] = arrayList.get(i9).longValue() * j4;
                }
            } else {
                long j5 = j2 / 1000000;
                str = str7;
                for (int i10 = 0; i10 < size; i10++) {
                    jArr[i10] = arrayList.get(i10).longValue() / j5;
                }
            }
            str2 = str6;
            str3 = str8;
            return new C2190a.b(str4, str5, i2, str2, j2, str, i3, i4, i5, i6, str3, formatArr, arrayList, jArr, C2344d0.m2314F(j3, 1000000L, j2));
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: d */
        public boolean mo2010d(String str) {
            return "c".equals(str);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2191b.a
        /* renamed from: k */
        public void mo2017k(XmlPullParser xmlPullParser) {
            int i2 = 1;
            if (!"c".equals(xmlPullParser.getName())) {
                String attributeValue = xmlPullParser.getAttributeValue(null, "Type");
                if (attributeValue == null) {
                    throw new b("Type");
                }
                if (!"audio".equalsIgnoreCase(attributeValue)) {
                    if ("video".equalsIgnoreCase(attributeValue)) {
                        i2 = 2;
                    } else {
                        if (!"text".equalsIgnoreCase(attributeValue)) {
                            throw new C2205l0(C1499a.m639y("Invalid key value[", attributeValue, "]"));
                        }
                        i2 = 3;
                    }
                }
                this.f5202g = i2;
                this.f5186d.add(Pair.create("Type", Integer.valueOf(i2)));
                if (this.f5202g == 3) {
                    this.f5203h = m2016j(xmlPullParser, "Subtype");
                } else {
                    this.f5203h = xmlPullParser.getAttributeValue(null, "Subtype");
                }
                this.f5186d.add(Pair.create("Subtype", this.f5203h));
                this.f5205j = xmlPullParser.getAttributeValue(null, "Name");
                this.f5206k = m2016j(xmlPullParser, "Url");
                this.f5207l = m2013g(xmlPullParser, "MaxWidth", -1);
                this.f5208m = m2013g(xmlPullParser, "MaxHeight", -1);
                this.f5209n = m2013g(xmlPullParser, "DisplayWidth", -1);
                this.f5210o = m2013g(xmlPullParser, "DisplayHeight", -1);
                String attributeValue2 = xmlPullParser.getAttributeValue(null, "Language");
                this.f5211p = attributeValue2;
                this.f5186d.add(Pair.create("Language", attributeValue2));
                long m2013g = m2013g(xmlPullParser, "TimeScale", -1);
                this.f5204i = m2013g;
                if (m2013g == -1) {
                    this.f5204i = ((Long) m2009c("TimeScale")).longValue();
                }
                this.f5212q = new ArrayList<>();
                return;
            }
            int size = this.f5212q.size();
            long m2014h = m2014h(xmlPullParser, "t", -9223372036854775807L);
            if (m2014h == -9223372036854775807L) {
                if (size == 0) {
                    m2014h = 0;
                } else {
                    if (this.f5213r == -1) {
                        throw new C2205l0("Unable to infer start time");
                    }
                    m2014h = this.f5213r + this.f5212q.get(size - 1).longValue();
                }
            }
            this.f5212q.add(Long.valueOf(m2014h));
            this.f5213r = m2014h(xmlPullParser, "d", -9223372036854775807L);
            long m2014h2 = m2014h(xmlPullParser, "r", 1L);
            if (m2014h2 > 1 && this.f5213r == -9223372036854775807L) {
                throw new C2205l0("Repeated chunk with unspecified duration");
            }
            while (true) {
                long j2 = i2;
                if (j2 >= m2014h2) {
                    return;
                }
                this.f5212q.add(Long.valueOf((this.f5213r * j2) + m2014h));
                i2++;
            }
        }
    }

    public C2191b() {
        try {
            this.f5182a = XmlPullParserFactory.newInstance();
        } catch (XmlPullParserException e2) {
            throw new RuntimeException("Couldn't create XmlPullParserFactory instance", e2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2285c0.a
    /* renamed from: a */
    public C2190a mo1900a(Uri uri, InputStream inputStream) {
        try {
            XmlPullParser newPullParser = this.f5182a.newPullParser();
            newPullParser.setInput(inputStream, null);
            return (C2190a) new e(null, uri.toString()).m2011e(newPullParser);
        } catch (XmlPullParserException e2) {
            throw new C2205l0(e2);
        }
    }
}
