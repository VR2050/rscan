package p005b.p199l.p200a.p201a.p236l1.p242r;

import android.text.Layout;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.r.d */
/* loaded from: classes.dex */
public final class C2237d {

    /* renamed from: a */
    public String f5528a;

    /* renamed from: b */
    public int f5529b;

    /* renamed from: c */
    public boolean f5530c;

    /* renamed from: d */
    public int f5531d;

    /* renamed from: e */
    public boolean f5532e;

    /* renamed from: f */
    public int f5533f = -1;

    /* renamed from: g */
    public int f5534g = -1;

    /* renamed from: h */
    public int f5535h = -1;

    /* renamed from: i */
    public int f5536i = -1;

    /* renamed from: j */
    public int f5537j = -1;

    /* renamed from: k */
    public float f5538k;

    /* renamed from: l */
    public String f5539l;

    /* renamed from: m */
    public Layout.Alignment f5540m;

    /* renamed from: a */
    public C2237d m2119a(C2237d c2237d) {
        if (c2237d != null) {
            if (!this.f5530c && c2237d.f5530c) {
                int i2 = c2237d.f5529b;
                C4195m.m4771I(true);
                this.f5529b = i2;
                this.f5530c = true;
            }
            if (this.f5535h == -1) {
                this.f5535h = c2237d.f5535h;
            }
            if (this.f5536i == -1) {
                this.f5536i = c2237d.f5536i;
            }
            if (this.f5528a == null) {
                this.f5528a = c2237d.f5528a;
            }
            if (this.f5533f == -1) {
                this.f5533f = c2237d.f5533f;
            }
            if (this.f5534g == -1) {
                this.f5534g = c2237d.f5534g;
            }
            if (this.f5540m == null) {
                this.f5540m = c2237d.f5540m;
            }
            if (this.f5537j == -1) {
                this.f5537j = c2237d.f5537j;
                this.f5538k = c2237d.f5538k;
            }
            if (!this.f5532e && c2237d.f5532e) {
                this.f5531d = c2237d.f5531d;
                this.f5532e = true;
            }
        }
        return this;
    }

    /* renamed from: b */
    public int m2120b() {
        int i2 = this.f5535h;
        if (i2 == -1 && this.f5536i == -1) {
            return -1;
        }
        return (i2 == 1 ? 1 : 0) | (this.f5536i == 1 ? 2 : 0);
    }
}
