package B2;

import h2.C0563i;
import i2.AbstractC0580h;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class t implements Iterable {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final b f410c = new b(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String[] f411b;

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final List f412a = new ArrayList(20);

        public final a a(String str, String str2) {
            t2.j.f(str, "name");
            t2.j.f(str2, "value");
            b bVar = t.f410c;
            bVar.d(str);
            bVar.e(str2, str);
            c(str, str2);
            return this;
        }

        public final a b(String str) {
            t2.j.f(str, "line");
            int I3 = z2.g.I(str, ':', 1, false, 4, null);
            if (I3 != -1) {
                String strSubstring = str.substring(0, I3);
                t2.j.e(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                String strSubstring2 = str.substring(I3 + 1);
                t2.j.e(strSubstring2, "(this as java.lang.String).substring(startIndex)");
                c(strSubstring, strSubstring2);
            } else if (str.charAt(0) == ':') {
                String strSubstring3 = str.substring(1);
                t2.j.e(strSubstring3, "(this as java.lang.String).substring(startIndex)");
                c("", strSubstring3);
            } else {
                c("", str);
            }
            return this;
        }

        public final a c(String str, String str2) {
            t2.j.f(str, "name");
            t2.j.f(str2, "value");
            this.f412a.add(str);
            this.f412a.add(z2.g.n0(str2).toString());
            return this;
        }

        public final a d(String str, String str2) {
            t2.j.f(str, "name");
            t2.j.f(str2, "value");
            t.f410c.d(str);
            c(str, str2);
            return this;
        }

        public final t e() {
            Object[] array = this.f412a.toArray(new String[0]);
            if (array != null) {
                return new t((String[]) array, null);
            }
            throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
        }

        public final String f(String str) {
            t2.j.f(str, "name");
            w2.a aVarH = w2.d.h(w2.d.g(this.f412a.size() - 2, 0), 2);
            int iA = aVarH.a();
            int iB = aVarH.b();
            int iC = aVarH.c();
            if (iC >= 0) {
                if (iA > iB) {
                    return null;
                }
            } else if (iA < iB) {
                return null;
            }
            while (!z2.g.j(str, (String) this.f412a.get(iA), true)) {
                if (iA == iB) {
                    return null;
                }
                iA += iC;
            }
            return (String) this.f412a.get(iA + 1);
        }

        public final List g() {
            return this.f412a;
        }

        public final a h(String str) {
            t2.j.f(str, "name");
            int i3 = 0;
            while (i3 < this.f412a.size()) {
                if (z2.g.j(str, (String) this.f412a.get(i3), true)) {
                    this.f412a.remove(i3);
                    this.f412a.remove(i3);
                    i3 -= 2;
                }
                i3 += 2;
            }
            return this;
        }

        public final a i(String str, String str2) {
            t2.j.f(str, "name");
            t2.j.f(str2, "value");
            b bVar = t.f410c;
            bVar.d(str);
            bVar.e(str2, str);
            h(str);
            c(str, str2);
            return this;
        }
    }

    public static final class b {
        private b() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void d(String str) {
            if (!(str.length() > 0)) {
                throw new IllegalArgumentException("name is empty");
            }
            int length = str.length();
            for (int i3 = 0; i3 < length; i3++) {
                char cCharAt = str.charAt(i3);
                if (!('!' <= cCharAt && '~' >= cCharAt)) {
                    throw new IllegalArgumentException(C2.c.q("Unexpected char %#04x at %d in header name: %s", Integer.valueOf(cCharAt), Integer.valueOf(i3), str).toString());
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void e(String str, String str2) {
            int length = str.length();
            for (int i3 = 0; i3 < length; i3++) {
                char cCharAt = str.charAt(i3);
                if (!(cCharAt == '\t' || (' ' <= cCharAt && '~' >= cCharAt))) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(C2.c.q("Unexpected char %#04x at %d in %s value", Integer.valueOf(cCharAt), Integer.valueOf(i3), str2));
                    sb.append(C2.c.E(str2) ? "" : ": " + str);
                    throw new IllegalArgumentException(sb.toString().toString());
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final String f(String[] strArr, String str) {
            w2.a aVarH = w2.d.h(w2.d.g(strArr.length - 2, 0), 2);
            int iA = aVarH.a();
            int iB = aVarH.b();
            int iC = aVarH.c();
            if (iC >= 0) {
                if (iA > iB) {
                    return null;
                }
            } else if (iA < iB) {
                return null;
            }
            while (!z2.g.j(str, strArr[iA], true)) {
                if (iA == iB) {
                    return null;
                }
                iA += iC;
            }
            return strArr[iA + 1];
        }

        public final t g(Map map) {
            t2.j.f(map, "$this$toHeaders");
            String[] strArr = new String[map.size() * 2];
            int i3 = 0;
            for (Map.Entry entry : map.entrySet()) {
                String str = (String) entry.getKey();
                String str2 = (String) entry.getValue();
                if (str == null) {
                    throw new NullPointerException("null cannot be cast to non-null type kotlin.CharSequence");
                }
                String string = z2.g.n0(str).toString();
                if (str2 == null) {
                    throw new NullPointerException("null cannot be cast to non-null type kotlin.CharSequence");
                }
                String string2 = z2.g.n0(str2).toString();
                d(string);
                e(string2, string);
                strArr[i3] = string;
                strArr[i3 + 1] = string2;
                i3 += 2;
            }
            return new t(strArr, null);
        }

        public final t h(String... strArr) throws CloneNotSupportedException {
            t2.j.f(strArr, "namesAndValues");
            if (!(strArr.length % 2 == 0)) {
                throw new IllegalArgumentException("Expected alternating header names and values");
            }
            Object objClone = strArr.clone();
            if (objClone == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<kotlin.String>");
            }
            String[] strArr2 = (String[]) objClone;
            int length = strArr2.length;
            for (int i3 = 0; i3 < length; i3++) {
                String str = strArr2[i3];
                if (!(str != null)) {
                    throw new IllegalArgumentException("Headers cannot be null");
                }
                if (str == null) {
                    throw new NullPointerException("null cannot be cast to non-null type kotlin.CharSequence");
                }
                strArr2[i3] = z2.g.n0(str).toString();
            }
            w2.a aVarH = w2.d.h(AbstractC0580h.p(strArr2), 2);
            int iA = aVarH.a();
            int iB = aVarH.b();
            int iC = aVarH.c();
            if (iC < 0 ? iA >= iB : iA <= iB) {
                while (true) {
                    String str2 = strArr2[iA];
                    String str3 = strArr2[iA + 1];
                    d(str2);
                    e(str3, str2);
                    if (iA == iB) {
                        break;
                    }
                    iA += iC;
                }
            }
            return new t(strArr2, null);
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    private t(String[] strArr) {
        this.f411b = strArr;
    }

    public static final t f(Map map) {
        return f410c.g(map);
    }

    public final String a(String str) {
        t2.j.f(str, "name");
        return f410c.f(this.f411b, str);
    }

    public final String b(int i3) {
        return this.f411b[i3 * 2];
    }

    public final Set c() {
        TreeSet treeSet = new TreeSet(z2.g.k(t2.w.f10219a));
        int size = size();
        for (int i3 = 0; i3 < size; i3++) {
            treeSet.add(b(i3));
        }
        Set setUnmodifiableSet = Collections.unmodifiableSet(treeSet);
        t2.j.e(setUnmodifiableSet, "Collections.unmodifiableSet(result)");
        return setUnmodifiableSet;
    }

    public final a e() {
        a aVar = new a();
        AbstractC0586n.r(aVar.g(), this.f411b);
        return aVar;
    }

    public boolean equals(Object obj) {
        return (obj instanceof t) && Arrays.equals(this.f411b, ((t) obj).f411b);
    }

    public final String h(int i3) {
        return this.f411b[(i3 * 2) + 1];
    }

    public int hashCode() {
        return Arrays.hashCode(this.f411b);
    }

    public final List i(String str) {
        t2.j.f(str, "name");
        int size = size();
        ArrayList arrayList = null;
        for (int i3 = 0; i3 < size; i3++) {
            if (z2.g.j(str, b(i3), true)) {
                if (arrayList == null) {
                    arrayList = new ArrayList(2);
                }
                arrayList.add(h(i3));
            }
        }
        if (arrayList == null) {
            return AbstractC0586n.g();
        }
        List listUnmodifiableList = Collections.unmodifiableList(arrayList);
        t2.j.e(listUnmodifiableList, "Collections.unmodifiableList(result)");
        return listUnmodifiableList;
    }

    @Override // java.lang.Iterable
    public Iterator iterator() {
        int size = size();
        C0563i[] c0563iArr = new C0563i[size];
        for (int i3 = 0; i3 < size; i3++) {
            c0563iArr[i3] = h2.n.a(b(i3), h(i3));
        }
        return t2.b.a(c0563iArr);
    }

    public final int size() {
        return this.f411b.length / 2;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        int size = size();
        for (int i3 = 0; i3 < size; i3++) {
            String strB = b(i3);
            String strH = h(i3);
            sb.append(strB);
            sb.append(": ");
            if (C2.c.E(strB)) {
                strH = "██";
            }
            sb.append(strH);
            sb.append("\n");
        }
        String string = sb.toString();
        t2.j.e(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }

    public /* synthetic */ t(String[] strArr, DefaultConstructorMarker defaultConstructorMarker) {
        this(strArr);
    }
}
