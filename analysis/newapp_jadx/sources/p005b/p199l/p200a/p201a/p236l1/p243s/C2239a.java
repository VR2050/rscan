package p005b.p199l.p200a.p201a.p236l1.p243s;

import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.UnderlineSpan;
import androidx.recyclerview.widget.ItemTouchHelper;
import java.nio.charset.Charset;
import java.util.List;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2208c;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.C2212g;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.l1.s.a */
/* loaded from: classes.dex */
public final class C2239a extends AbstractC2208c {

    /* renamed from: n */
    public final C2360t f5546n;

    /* renamed from: o */
    public boolean f5547o;

    /* renamed from: p */
    public int f5548p;

    /* renamed from: q */
    public int f5549q;

    /* renamed from: r */
    public String f5550r;

    /* renamed from: s */
    public float f5551s;

    /* renamed from: t */
    public int f5552t;

    public C2239a(List<byte[]> list) {
        super("Tx3gDecoder");
        this.f5546n = new C2360t();
        if (list == null || list.size() != 1 || (list.get(0).length != 48 && list.get(0).length != 53)) {
            this.f5548p = 0;
            this.f5549q = -1;
            this.f5550r = "sans-serif";
            this.f5547o = false;
            this.f5551s = 0.85f;
            return;
        }
        byte[] bArr = list.get(0);
        this.f5548p = bArr[24];
        this.f5549q = ((bArr[26] & 255) << 24) | ((bArr[27] & 255) << 16) | ((bArr[28] & 255) << 8) | (bArr[29] & 255);
        this.f5550r = "Serif".equals(C2344d0.m2333k(bArr, 43, bArr.length - 43)) ? "serif" : "sans-serif";
        int i2 = bArr[25] * 20;
        this.f5552t = i2;
        boolean z = (bArr[0] & 32) != 0;
        this.f5547o = z;
        if (!z) {
            this.f5551s = 0.85f;
            return;
        }
        float f2 = ((bArr[11] & 255) | ((bArr[10] & 255) << 8)) / i2;
        this.f5551s = f2;
        this.f5551s = C2344d0.m2328f(f2, 0.0f, 0.95f);
    }

    /* renamed from: k */
    public static void m2121k(boolean z) {
        if (!z) {
            throw new C2212g("Unexpected subtitle format.");
        }
    }

    /* renamed from: l */
    public static void m2122l(SpannableStringBuilder spannableStringBuilder, int i2, int i3, int i4, int i5, int i6) {
        if (i2 != i3) {
            int i7 = i6 | 33;
            boolean z = (i2 & 1) != 0;
            boolean z2 = (i2 & 2) != 0;
            if (z) {
                if (z2) {
                    spannableStringBuilder.setSpan(new StyleSpan(3), i4, i5, i7);
                } else {
                    spannableStringBuilder.setSpan(new StyleSpan(1), i4, i5, i7);
                }
            } else if (z2) {
                spannableStringBuilder.setSpan(new StyleSpan(2), i4, i5, i7);
            }
            boolean z3 = (i2 & 4) != 0;
            if (z3) {
                spannableStringBuilder.setSpan(new UnderlineSpan(), i4, i5, i7);
            }
            if (z3 || z || z2) {
                return;
            }
            spannableStringBuilder.setSpan(new StyleSpan(0), i4, i5, i7);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.AbstractC2208c
    /* renamed from: j */
    public InterfaceC2210e mo2047j(byte[] bArr, int i2, boolean z) {
        String m2583o;
        C2360t c2360t = this.f5546n;
        c2360t.f6133a = bArr;
        c2360t.f6135c = i2;
        c2360t.f6134b = 0;
        int i3 = 1;
        m2121k(c2360t.m2569a() >= 2);
        int m2590v = c2360t.m2590v();
        if (m2590v == 0) {
            m2583o = "";
        } else {
            if (c2360t.m2569a() >= 2) {
                byte[] bArr2 = c2360t.f6133a;
                int i4 = c2360t.f6134b;
                char c2 = (char) ((bArr2[i4 + 1] & 255) | ((bArr2[i4] & 255) << 8));
                if (c2 == 65279 || c2 == 65534) {
                    m2583o = c2360t.m2583o(m2590v, Charset.forName("UTF-16"));
                }
            }
            m2583o = c2360t.m2583o(m2590v, Charset.forName("UTF-8"));
        }
        if (m2583o.isEmpty()) {
            return C2240b.f5553c;
        }
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(m2583o);
        m2122l(spannableStringBuilder, this.f5548p, 0, 0, spannableStringBuilder.length(), ItemTouchHelper.ACTION_MODE_DRAG_MASK);
        int i5 = this.f5549q;
        int length = spannableStringBuilder.length();
        if (i5 != -1) {
            spannableStringBuilder.setSpan(new ForegroundColorSpan((i5 >>> 8) | ((i5 & 255) << 24)), 0, length, 16711713);
        }
        String str = this.f5550r;
        int length2 = spannableStringBuilder.length();
        if (str != "sans-serif") {
            spannableStringBuilder.setSpan(new TypefaceSpan(str), 0, length2, 16711713);
        }
        float f2 = this.f5551s;
        while (this.f5546n.m2569a() >= 8) {
            C2360t c2360t2 = this.f5546n;
            int i6 = c2360t2.f6134b;
            int m2573e = c2360t2.m2573e();
            int m2573e2 = this.f5546n.m2573e();
            if (m2573e2 == 1937013100) {
                m2121k(this.f5546n.m2569a() >= 2);
                int m2590v2 = this.f5546n.m2590v();
                int i7 = 0;
                while (i7 < m2590v2) {
                    C2360t c2360t3 = this.f5546n;
                    m2121k(c2360t3.m2569a() >= 12);
                    int m2590v3 = c2360t3.m2590v();
                    int m2590v4 = c2360t3.m2590v();
                    c2360t3.m2568D(2);
                    int m2585q = c2360t3.m2585q();
                    c2360t3.m2568D(i3);
                    int m2573e3 = c2360t3.m2573e();
                    int i8 = i7;
                    m2122l(spannableStringBuilder, m2585q, this.f5548p, m2590v3, m2590v4, 0);
                    if (m2573e3 != this.f5549q) {
                        spannableStringBuilder.setSpan(new ForegroundColorSpan((m2573e3 >>> 8) | ((m2573e3 & 255) << 24)), m2590v3, m2590v4, 33);
                    }
                    i7 = i8 + 1;
                    i3 = 1;
                }
            } else if (m2573e2 == 1952608120 && this.f5547o) {
                m2121k(this.f5546n.m2569a() >= 2);
                f2 = C2344d0.m2328f(this.f5546n.m2590v() / this.f5552t, 0.0f, 0.95f);
            }
            this.f5546n.m2567C(i6 + m2573e);
            i3 = 1;
        }
        return new C2240b(new C2207b(spannableStringBuilder, null, f2, 0, 0, -3.4028235E38f, Integer.MIN_VALUE, -3.4028235E38f));
    }
}
