package p476m.p477a.p485b.p493l0;

import java.util.ArrayList;
import java.util.BitSet;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4802g;
import p476m.p477a.p485b.InterfaceC4906z;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.l0.d */
/* loaded from: classes3.dex */
public class C4856d {

    /* renamed from: a */
    public static final C4856d f12434a = new C4856d();

    /* renamed from: b */
    public static final BitSet f12435b;

    /* renamed from: c */
    public static final BitSet f12436c;

    static {
        int[] iArr = {61, 59, 44};
        BitSet bitSet = new BitSet();
        for (int i2 = 0; i2 < 3; i2++) {
            bitSet.set(iArr[i2]);
        }
        f12435b = bitSet;
        int[] iArr2 = {59, 44};
        BitSet bitSet2 = new BitSet();
        for (int i3 = 0; i3 < 2; i3++) {
            bitSet2.set(iArr2[i3]);
        }
        f12436c = bitSet2;
    }

    /* renamed from: a */
    public InterfaceC4802g[] m5522a(C4893b c4893b, C4871s c4871s) {
        InterfaceC4906z[] interfaceC4906zArr;
        C4855c c4855c;
        C2354n.m2470e1(c4893b, "Char array buffer");
        C2354n.m2470e1(c4871s, "Parser cursor");
        ArrayList arrayList = new ArrayList();
        while (!c4871s.m5541a()) {
            C2354n.m2470e1(c4893b, "Char array buffer");
            C2354n.m2470e1(c4871s, "Parser cursor");
            InterfaceC4906z m5523b = m5523b(c4893b, c4871s);
            if (!c4871s.m5541a()) {
                if (c4893b.f12497c[c4871s.f12474b - 1] != ',') {
                    C2354n.m2470e1(c4893b, "Char array buffer");
                    C2354n.m2470e1(c4871s, "Parser cursor");
                    int i2 = c4871s.f12474b;
                    int i3 = c4871s.f12473a;
                    int i4 = i2;
                    while (i2 < i3 && C4872t.m5543a(c4893b.f12497c[i2])) {
                        i4++;
                        i2++;
                    }
                    c4871s.m5542b(i4);
                    ArrayList arrayList2 = new ArrayList();
                    while (!c4871s.m5541a()) {
                        arrayList2.add(m5523b(c4893b, c4871s));
                        if (c4893b.f12497c[c4871s.f12474b - 1] == ',') {
                            break;
                        }
                    }
                    interfaceC4906zArr = (InterfaceC4906z[]) arrayList2.toArray(new InterfaceC4906z[arrayList2.size()]);
                    C4863k c4863k = (C4863k) m5523b;
                    c4855c = new C4855c(c4863k.f12456c, c4863k.f12457e, interfaceC4906zArr);
                    if (c4855c.f12431c.isEmpty() || c4855c.f12432e != null) {
                        arrayList.add(c4855c);
                    }
                }
            }
            interfaceC4906zArr = null;
            C4863k c4863k2 = (C4863k) m5523b;
            c4855c = new C4855c(c4863k2.f12456c, c4863k2.f12457e, interfaceC4906zArr);
            if (c4855c.f12431c.isEmpty()) {
            }
            arrayList.add(c4855c);
        }
        return (InterfaceC4802g[]) arrayList.toArray(new InterfaceC4802g[arrayList.size()]);
    }

    /* renamed from: b */
    public InterfaceC4906z m5523b(C4893b c4893b, C4871s c4871s) {
        C2354n.m2470e1(c4893b, "Char array buffer");
        C2354n.m2470e1(c4871s, "Parser cursor");
        BitSet bitSet = f12435b;
        StringBuilder sb = new StringBuilder();
        loop0: while (true) {
            boolean z = false;
            while (!c4871s.m5541a()) {
                char c2 = c4893b.f12497c[c4871s.f12474b];
                if (bitSet != null && bitSet.get(c2)) {
                    break loop0;
                }
                if (C4872t.m5543a(c2)) {
                    int i2 = c4871s.f12474b;
                    int i3 = c4871s.f12473a;
                    int i4 = i2;
                    while (i2 < i3 && C4872t.m5543a(c4893b.f12497c[i2])) {
                        i4++;
                        i2++;
                    }
                    c4871s.m5542b(i4);
                    z = true;
                } else {
                    if (z && sb.length() > 0) {
                        sb.append(' ');
                    }
                    int i5 = c4871s.f12474b;
                    int i6 = c4871s.f12473a;
                    int i7 = i5;
                    while (i5 < i6) {
                        char c3 = c4893b.f12497c[i5];
                        if ((bitSet == null || !bitSet.get(c3)) && !C4872t.m5543a(c3)) {
                            i7++;
                            sb.append(c3);
                            i5++;
                        }
                        c4871s.m5542b(i7);
                    }
                    c4871s.m5542b(i7);
                }
            }
            break loop0;
        }
        String sb2 = sb.toString();
        if (c4871s.m5541a()) {
            return new C4863k(sb2, null);
        }
        int i8 = c4871s.f12474b;
        char c4 = c4893b.f12497c[i8];
        c4871s.m5542b(i8 + 1);
        if (c4 != '=') {
            return new C4863k(sb2, null);
        }
        BitSet bitSet2 = f12436c;
        StringBuilder sb3 = new StringBuilder();
        loop2: while (true) {
            boolean z2 = false;
            while (!c4871s.m5541a()) {
                char c5 = c4893b.f12497c[c4871s.f12474b];
                if (bitSet2 != null && bitSet2.get(c5)) {
                    break loop2;
                }
                if (C4872t.m5543a(c5)) {
                    int i9 = c4871s.f12474b;
                    int i10 = c4871s.f12473a;
                    int i11 = i9;
                    while (i9 < i10 && C4872t.m5543a(c4893b.f12497c[i9])) {
                        i11++;
                        i9++;
                    }
                    c4871s.m5542b(i11);
                    z2 = true;
                } else if (c5 == '\"') {
                    if (z2 && sb3.length() > 0) {
                        sb3.append(' ');
                    }
                    if (!c4871s.m5541a()) {
                        int i12 = c4871s.f12474b;
                        int i13 = c4871s.f12473a;
                        if (c4893b.f12497c[i12] == '\"') {
                            int i14 = i12 + 1;
                            int i15 = i14;
                            boolean z3 = false;
                            while (true) {
                                if (i14 >= i13) {
                                    break;
                                }
                                char c6 = c4893b.f12497c[i14];
                                if (z3) {
                                    if (c6 != '\"' && c6 != '\\') {
                                        sb3.append('\\');
                                    }
                                    sb3.append(c6);
                                    z3 = false;
                                } else {
                                    if (c6 == '\"') {
                                        i15++;
                                        break;
                                    }
                                    if (c6 == '\\') {
                                        z3 = true;
                                    } else if (c6 != '\r' && c6 != '\n') {
                                        sb3.append(c6);
                                    }
                                }
                                i14++;
                                i15++;
                            }
                            c4871s.m5542b(i15);
                        }
                    }
                } else {
                    if (z2 && sb3.length() > 0) {
                        sb3.append(' ');
                    }
                    int i16 = c4871s.f12474b;
                    int i17 = c4871s.f12473a;
                    int i18 = i16;
                    while (i16 < i17) {
                        char c7 = c4893b.f12497c[i16];
                        if ((bitSet2 != null && bitSet2.get(c7)) || C4872t.m5543a(c7) || c7 == '\"') {
                            break;
                        }
                        i18++;
                        sb3.append(c7);
                        i16++;
                    }
                    c4871s.m5542b(i18);
                }
            }
            break loop2;
        }
        String sb4 = sb3.toString();
        if (!c4871s.m5541a()) {
            c4871s.m5542b(c4871s.f12474b + 1);
        }
        return new C4863k(sb2, sb4);
    }
}
