package androidx.core.content.res;

import android.content.res.Resources;
import android.content.res.TypedArray;
import android.util.Base64;
import android.util.Xml;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import m.AbstractC0625c;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/* JADX INFO: loaded from: classes.dex */
public abstract class d {

    static class a {
        static int a(TypedArray typedArray, int i3) {
            return typedArray.getType(i3);
        }
    }

    public interface b {
    }

    public static final class c implements b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final C0058d[] f4282a;

        public c(C0058d[] c0058dArr) {
            this.f4282a = c0058dArr;
        }

        public C0058d[] a() {
            return this.f4282a;
        }
    }

    /* JADX INFO: renamed from: androidx.core.content.res.d$d, reason: collision with other inner class name */
    public static final class C0058d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f4283a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f4284b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final boolean f4285c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final String f4286d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final int f4287e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final int f4288f;

        public C0058d(String str, int i3, boolean z3, String str2, int i4, int i5) {
            this.f4283a = str;
            this.f4284b = i3;
            this.f4285c = z3;
            this.f4286d = str2;
            this.f4287e = i4;
            this.f4288f = i5;
        }

        public String a() {
            return this.f4283a;
        }

        public int b() {
            return this.f4288f;
        }

        public int c() {
            return this.f4287e;
        }

        public String d() {
            return this.f4286d;
        }

        public int e() {
            return this.f4284b;
        }

        public boolean f() {
            return this.f4285c;
        }
    }

    public static final class e implements b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final p.e f4289a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f4290b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f4291c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final String f4292d;

        public e(p.e eVar, int i3, int i4, String str) {
            this.f4289a = eVar;
            this.f4291c = i3;
            this.f4290b = i4;
            this.f4292d = str;
        }

        public int a() {
            return this.f4291c;
        }

        public p.e b() {
            return this.f4289a;
        }

        public String c() {
            return this.f4292d;
        }

        public int d() {
            return this.f4290b;
        }
    }

    private static int a(TypedArray typedArray, int i3) {
        return a.a(typedArray, i3);
    }

    public static b b(XmlPullParser xmlPullParser, Resources resources) throws XmlPullParserException, IOException {
        int next;
        do {
            next = xmlPullParser.next();
            if (next == 2) {
                break;
            }
        } while (next != 1);
        if (next == 2) {
            return d(xmlPullParser, resources);
        }
        throw new XmlPullParserException("No start tag found");
    }

    public static List c(Resources resources, int i3) {
        if (i3 == 0) {
            return Collections.emptyList();
        }
        TypedArray typedArrayObtainTypedArray = resources.obtainTypedArray(i3);
        try {
            if (typedArrayObtainTypedArray.length() == 0) {
                return Collections.emptyList();
            }
            ArrayList arrayList = new ArrayList();
            if (a(typedArrayObtainTypedArray, 0) == 1) {
                for (int i4 = 0; i4 < typedArrayObtainTypedArray.length(); i4++) {
                    int resourceId = typedArrayObtainTypedArray.getResourceId(i4, 0);
                    if (resourceId != 0) {
                        arrayList.add(h(resources.getStringArray(resourceId)));
                    }
                }
            } else {
                arrayList.add(h(resources.getStringArray(i3)));
            }
            return arrayList;
        } finally {
            typedArrayObtainTypedArray.recycle();
        }
    }

    private static b d(XmlPullParser xmlPullParser, Resources resources) throws XmlPullParserException, IOException {
        xmlPullParser.require(2, null, "font-family");
        if (xmlPullParser.getName().equals("font-family")) {
            return e(xmlPullParser, resources);
        }
        g(xmlPullParser);
        return null;
    }

    private static b e(XmlPullParser xmlPullParser, Resources resources) throws XmlPullParserException, IOException {
        TypedArray typedArrayObtainAttributes = resources.obtainAttributes(Xml.asAttributeSet(xmlPullParser), AbstractC0625c.f9580h);
        String string = typedArrayObtainAttributes.getString(AbstractC0625c.f9581i);
        String string2 = typedArrayObtainAttributes.getString(AbstractC0625c.f9585m);
        String string3 = typedArrayObtainAttributes.getString(AbstractC0625c.f9586n);
        int resourceId = typedArrayObtainAttributes.getResourceId(AbstractC0625c.f9582j, 0);
        int integer = typedArrayObtainAttributes.getInteger(AbstractC0625c.f9583k, 1);
        int integer2 = typedArrayObtainAttributes.getInteger(AbstractC0625c.f9584l, 500);
        String string4 = typedArrayObtainAttributes.getString(AbstractC0625c.f9587o);
        typedArrayObtainAttributes.recycle();
        if (string != null && string2 != null && string3 != null) {
            while (xmlPullParser.next() != 3) {
                g(xmlPullParser);
            }
            return new e(new p.e(string, string2, string3, c(resources, resourceId)), integer, integer2, string4);
        }
        ArrayList arrayList = new ArrayList();
        while (xmlPullParser.next() != 3) {
            if (xmlPullParser.getEventType() == 2) {
                if (xmlPullParser.getName().equals("font")) {
                    arrayList.add(f(xmlPullParser, resources));
                } else {
                    g(xmlPullParser);
                }
            }
        }
        if (arrayList.isEmpty()) {
            return null;
        }
        return new c((C0058d[]) arrayList.toArray(new C0058d[0]));
    }

    private static C0058d f(XmlPullParser xmlPullParser, Resources resources) throws XmlPullParserException, IOException {
        TypedArray typedArrayObtainAttributes = resources.obtainAttributes(Xml.asAttributeSet(xmlPullParser), AbstractC0625c.f9588p);
        int i3 = typedArrayObtainAttributes.getInt(typedArrayObtainAttributes.hasValue(AbstractC0625c.f9597y) ? AbstractC0625c.f9597y : AbstractC0625c.f9590r, 400);
        boolean z3 = 1 == typedArrayObtainAttributes.getInt(typedArrayObtainAttributes.hasValue(AbstractC0625c.f9595w) ? AbstractC0625c.f9595w : AbstractC0625c.f9591s, 0);
        int i4 = typedArrayObtainAttributes.hasValue(AbstractC0625c.f9598z) ? AbstractC0625c.f9598z : AbstractC0625c.f9592t;
        String string = typedArrayObtainAttributes.getString(typedArrayObtainAttributes.hasValue(AbstractC0625c.f9596x) ? AbstractC0625c.f9596x : AbstractC0625c.f9593u);
        int i5 = typedArrayObtainAttributes.getInt(i4, 0);
        int i6 = typedArrayObtainAttributes.hasValue(AbstractC0625c.f9594v) ? AbstractC0625c.f9594v : AbstractC0625c.f9589q;
        int resourceId = typedArrayObtainAttributes.getResourceId(i6, 0);
        String string2 = typedArrayObtainAttributes.getString(i6);
        typedArrayObtainAttributes.recycle();
        while (xmlPullParser.next() != 3) {
            g(xmlPullParser);
        }
        return new C0058d(string2, i3, z3, string, i5, resourceId);
    }

    private static void g(XmlPullParser xmlPullParser) throws XmlPullParserException, IOException {
        int i3 = 1;
        while (i3 > 0) {
            int next = xmlPullParser.next();
            if (next == 2) {
                i3++;
            } else if (next == 3) {
                i3--;
            }
        }
    }

    private static List h(String[] strArr) {
        ArrayList arrayList = new ArrayList();
        for (String str : strArr) {
            arrayList.add(Base64.decode(str, 0));
        }
        return arrayList;
    }
}
