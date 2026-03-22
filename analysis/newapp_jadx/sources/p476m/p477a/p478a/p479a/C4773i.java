package p476m.p477a.p478a.p479a;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import p476m.p477a.p478a.p479a.p481m.p482d.C4782b;

/* renamed from: m.a.a.a.i */
/* loaded from: classes3.dex */
public class C4773i {

    /* renamed from: a */
    public char[] f12228a = null;

    /* renamed from: b */
    public int f12229b = 0;

    /* renamed from: c */
    public int f12230c = 0;

    /* renamed from: d */
    public int f12231d = 0;

    /* renamed from: e */
    public int f12232e = 0;

    /* renamed from: f */
    public boolean f12233f = false;

    /* renamed from: a */
    public final String m5449a(boolean z) {
        while (true) {
            int i2 = this.f12231d;
            if (i2 >= this.f12232e || !Character.isWhitespace(this.f12228a[i2])) {
                break;
            }
            this.f12231d++;
        }
        while (true) {
            int i3 = this.f12232e;
            if (i3 <= this.f12231d || !Character.isWhitespace(this.f12228a[i3 - 1])) {
                break;
            }
            this.f12232e--;
        }
        if (z) {
            int i4 = this.f12232e;
            int i5 = this.f12231d;
            if (i4 - i5 >= 2) {
                char[] cArr = this.f12228a;
                if (cArr[i5] == '\"' && cArr[i4 - 1] == '\"') {
                    this.f12231d = i5 + 1;
                    this.f12232e = i4 - 1;
                }
            }
        }
        if (this.f12232e <= this.f12231d) {
            return null;
        }
        char[] cArr2 = this.f12228a;
        int i6 = this.f12231d;
        return new String(cArr2, i6, this.f12232e - i6);
    }

    /* renamed from: b */
    public final boolean m5450b() {
        return this.f12229b < this.f12230c;
    }

    /* renamed from: c */
    public final boolean m5451c(char c2, char[] cArr) {
        for (char c3 : cArr) {
            if (c2 == c3) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: d */
    public Map<String, String> m5452d(String str, char c2) {
        if (str == null) {
            return new HashMap();
        }
        char[] charArray = str.toCharArray();
        if (charArray == null) {
            return new HashMap();
        }
        int length = charArray.length;
        HashMap hashMap = new HashMap();
        this.f12228a = charArray;
        this.f12229b = 0;
        this.f12230c = length;
        while (m5450b()) {
            char[] cArr = {'=', c2};
            int i2 = this.f12229b;
            this.f12231d = i2;
            this.f12232e = i2;
            while (m5450b() && !m5451c(this.f12228a[this.f12229b], cArr)) {
                this.f12232e++;
                this.f12229b++;
            }
            String m5449a = m5449a(false);
            String str2 = null;
            if (m5450b()) {
                int i3 = this.f12229b;
                if (charArray[i3] == '=') {
                    int i4 = i3 + 1;
                    this.f12229b = i4;
                    char[] cArr2 = {c2};
                    this.f12231d = i4;
                    this.f12232e = i4;
                    boolean z = false;
                    boolean z2 = false;
                    while (m5450b()) {
                        char c3 = this.f12228a[this.f12229b];
                        if (!z && m5451c(c3, cArr2)) {
                            break;
                        }
                        if (!z2 && c3 == '\"') {
                            z = !z;
                        }
                        z2 = !z2 && c3 == '\\';
                        this.f12232e++;
                        this.f12229b++;
                    }
                    str2 = m5449a(true);
                    if (str2 != null) {
                        try {
                            str2 = C4782b.m5461a(str2);
                        } catch (UnsupportedEncodingException unused) {
                        }
                    }
                }
            }
            if (m5450b()) {
                int i5 = this.f12229b;
                if (charArray[i5] == c2) {
                    this.f12229b = i5 + 1;
                }
            }
            if (m5449a != null && m5449a.length() > 0) {
                if (this.f12233f) {
                    m5449a = m5449a.toLowerCase(Locale.ENGLISH);
                }
                hashMap.put(m5449a, str2);
            }
        }
        return hashMap;
    }
}
