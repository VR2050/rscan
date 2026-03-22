package p474l;

import java.util.List;
import java.util.RandomAccess;
import kotlin.collections.AbstractList;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.q */
/* loaded from: classes3.dex */
public final class C4755q extends AbstractList<C4747i> implements RandomAccess {

    /* renamed from: c */
    public static final a f12155c = new a(null);

    /* renamed from: e */
    @NotNull
    public final C4747i[] f12156e;

    /* renamed from: f */
    @NotNull
    public final int[] f12157f;

    /* renamed from: l.q$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: a */
        public final void m5415a(long j2, C4744f c4744f, int i2, List<? extends C4747i> list, int i3, int i4, List<Integer> list2) {
            int i5;
            int i6;
            int i7;
            int i8;
            C4744f c4744f2;
            int i9 = i2;
            if (!(i3 < i4)) {
                throw new IllegalArgumentException("Failed requirement.".toString());
            }
            for (int i10 = i3; i10 < i4; i10++) {
                if (!(list.get(i10).mo5400c() >= i9)) {
                    throw new IllegalArgumentException("Failed requirement.".toString());
                }
            }
            C4747i c4747i = list.get(i3);
            C4747i c4747i2 = list.get(i4 - 1);
            if (i9 == c4747i.mo5400c()) {
                int intValue = list2.get(i3).intValue();
                int i11 = i3 + 1;
                C4747i c4747i3 = list.get(i11);
                i5 = i11;
                i6 = intValue;
                c4747i = c4747i3;
            } else {
                i5 = i3;
                i6 = -1;
            }
            if (c4747i.mo5403f(i9) == c4747i2.mo5403f(i9)) {
                int min = Math.min(c4747i.mo5400c(), c4747i2.mo5400c());
                int i12 = 0;
                for (int i13 = i9; i13 < min && c4747i.mo5403f(i13) == c4747i2.mo5403f(i13); i13++) {
                    i12++;
                }
                long m5416b = m5416b(c4744f) + j2 + 2 + i12 + 1;
                c4744f.m5378d0(-i12);
                c4744f.m5378d0(i6);
                int i14 = i9 + i12;
                while (i9 < i14) {
                    c4744f.m5378d0(c4747i.mo5403f(i9) & 255);
                    i9++;
                }
                if (i5 + 1 == i4) {
                    if (!(i14 == list.get(i5).mo5400c())) {
                        throw new IllegalStateException("Check failed.".toString());
                    }
                    c4744f.m5378d0(list2.get(i5).intValue());
                    return;
                } else {
                    C4744f c4744f3 = new C4744f();
                    c4744f.m5378d0(((int) (m5416b(c4744f3) + m5416b)) * (-1));
                    m5415a(m5416b, c4744f3, i14, list, i5, i4, list2);
                    c4744f.mo5396y(c4744f3);
                    return;
                }
            }
            int i15 = 1;
            for (int i16 = i5 + 1; i16 < i4; i16++) {
                if (list.get(i16 - 1).mo5403f(i9) != list.get(i16).mo5403f(i9)) {
                    i15++;
                }
            }
            long m5416b2 = m5416b(c4744f) + j2 + 2 + (i15 * 2);
            c4744f.m5378d0(i15);
            c4744f.m5378d0(i6);
            for (int i17 = i5; i17 < i4; i17++) {
                byte mo5403f = list.get(i17).mo5403f(i9);
                if (i17 == i5 || mo5403f != list.get(i17 - 1).mo5403f(i9)) {
                    c4744f.m5378d0(mo5403f & 255);
                }
            }
            C4744f c4744f4 = new C4744f();
            while (i5 < i4) {
                byte mo5403f2 = list.get(i5).mo5403f(i9);
                int i18 = i5 + 1;
                int i19 = i18;
                while (true) {
                    if (i19 >= i4) {
                        i7 = i4;
                        break;
                    } else {
                        if (mo5403f2 != list.get(i19).mo5403f(i9)) {
                            i7 = i19;
                            break;
                        }
                        i19++;
                    }
                }
                if (i18 == i7 && i9 + 1 == list.get(i5).mo5400c()) {
                    c4744f.m5378d0(list2.get(i5).intValue());
                    i8 = i7;
                    c4744f2 = c4744f4;
                } else {
                    c4744f.m5378d0(((int) (m5416b(c4744f4) + m5416b2)) * (-1));
                    i8 = i7;
                    c4744f2 = c4744f4;
                    m5415a(m5416b2, c4744f4, i9 + 1, list, i5, i7, list2);
                }
                c4744f4 = c4744f2;
                i5 = i8;
            }
            c4744f.mo5396y(c4744f4);
        }

        /* renamed from: b */
        public final long m5416b(C4744f c4744f) {
            return c4744f.f12133e / 4;
        }
    }

    public C4755q(C4747i[] c4747iArr, int[] iArr, DefaultConstructorMarker defaultConstructorMarker) {
        this.f12156e = c4747iArr;
        this.f12157f = iArr;
    }

    @Override // kotlin.collections.AbstractCollection, java.util.Collection
    public final /* bridge */ boolean contains(Object obj) {
        if (obj instanceof C4747i) {
            return super.contains((C4747i) obj);
        }
        return false;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public Object get(int i2) {
        return this.f12156e[i2];
    }

    @Override // kotlin.collections.AbstractList, kotlin.collections.AbstractCollection
    /* renamed from: getSize */
    public int get_size() {
        return this.f12156e.length;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public final /* bridge */ int indexOf(Object obj) {
        if (obj instanceof C4747i) {
            return super.indexOf((C4747i) obj);
        }
        return -1;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public final /* bridge */ int lastIndexOf(Object obj) {
        if (obj instanceof C4747i) {
            return super.lastIndexOf((C4747i) obj);
        }
        return -1;
    }
}
