package p005b.p199l.p200a.p201a.p250p1;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import p005b.p199l.p200a.p201a.p250p1.C2364x;

/* renamed from: b.l.a.a.p1.x */
/* loaded from: classes.dex */
public class C2364x {

    /* renamed from: a */
    public static final /* synthetic */ int f6141a = 0;

    /* renamed from: b */
    public final int f6142b;

    /* renamed from: f */
    public int f6146f;

    /* renamed from: g */
    public int f6147g;

    /* renamed from: h */
    public int f6148h;

    /* renamed from: d */
    public final b[] f6144d = new b[5];

    /* renamed from: c */
    public final ArrayList<b> f6143c = new ArrayList<>();

    /* renamed from: e */
    public int f6145e = -1;

    /* renamed from: b.l.a.a.p1.x$b */
    public static class b {

        /* renamed from: a */
        public int f6149a;

        /* renamed from: b */
        public int f6150b;

        /* renamed from: c */
        public float f6151c;

        public b() {
        }

        public b(a aVar) {
        }
    }

    public C2364x(int i2) {
        this.f6142b = i2;
    }

    /* renamed from: a */
    public void m2606a(int i2, float f2) {
        b bVar;
        if (this.f6145e != 1) {
            Collections.sort(this.f6143c, new Comparator() { // from class: b.l.a.a.p1.b
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    int i3 = C2364x.f6141a;
                    return ((C2364x.b) obj).f6149a - ((C2364x.b) obj2).f6149a;
                }
            });
            this.f6145e = 1;
        }
        int i3 = this.f6148h;
        if (i3 > 0) {
            b[] bVarArr = this.f6144d;
            int i4 = i3 - 1;
            this.f6148h = i4;
            bVar = bVarArr[i4];
        } else {
            bVar = new b(null);
        }
        int i5 = this.f6146f;
        this.f6146f = i5 + 1;
        bVar.f6149a = i5;
        bVar.f6150b = i2;
        bVar.f6151c = f2;
        this.f6143c.add(bVar);
        this.f6147g += i2;
        while (true) {
            int i6 = this.f6147g;
            int i7 = this.f6142b;
            if (i6 <= i7) {
                return;
            }
            int i8 = i6 - i7;
            b bVar2 = this.f6143c.get(0);
            int i9 = bVar2.f6150b;
            if (i9 <= i8) {
                this.f6147g -= i9;
                this.f6143c.remove(0);
                int i10 = this.f6148h;
                if (i10 < 5) {
                    b[] bVarArr2 = this.f6144d;
                    this.f6148h = i10 + 1;
                    bVarArr2[i10] = bVar2;
                }
            } else {
                bVar2.f6150b = i9 - i8;
                this.f6147g -= i8;
            }
        }
    }

    /* renamed from: b */
    public float m2607b(float f2) {
        if (this.f6145e != 0) {
            Collections.sort(this.f6143c, new Comparator() { // from class: b.l.a.a.p1.c
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    int i2 = C2364x.f6141a;
                    return Float.compare(((C2364x.b) obj).f6151c, ((C2364x.b) obj2).f6151c);
                }
            });
            this.f6145e = 0;
        }
        float f3 = f2 * this.f6147g;
        int i2 = 0;
        for (int i3 = 0; i3 < this.f6143c.size(); i3++) {
            b bVar = this.f6143c.get(i3);
            i2 += bVar.f6150b;
            if (i2 >= f3) {
                return bVar.f6151c;
            }
        }
        if (this.f6143c.isEmpty()) {
            return Float.NaN;
        }
        return this.f6143c.get(r5.size() - 1).f6151c;
    }
}
