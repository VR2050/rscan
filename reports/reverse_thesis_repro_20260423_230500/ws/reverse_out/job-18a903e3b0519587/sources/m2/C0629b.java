package m2;

import i2.AbstractC0574b;
import i2.AbstractC0580h;
import java.io.Serializable;
import kotlin.enums.EnumEntries;
import t2.j;

/* JADX INFO: renamed from: m2.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
final class C0629b extends AbstractC0574b implements EnumEntries, Serializable {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Enum[] f9675c;

    public C0629b(Enum[] enumArr) {
        j.f(enumArr, "entries");
        this.f9675c = enumArr;
    }

    @Override // i2.AbstractC0573a
    public int a() {
        return this.f9675c.length;
    }

    public boolean b(Enum r3) {
        j.f(r3, "element");
        return ((Enum) AbstractC0580h.s(this.f9675c, r3.ordinal())) == r3;
    }

    @Override // i2.AbstractC0574b, java.util.List
    /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
    public Enum get(int i3) {
        AbstractC0574b.f9337b.a(i3, this.f9675c.length);
        return this.f9675c[i3];
    }

    @Override // i2.AbstractC0573a, java.util.Collection, java.util.List
    public final /* bridge */ boolean contains(Object obj) {
        if (obj instanceof Enum) {
            return b((Enum) obj);
        }
        return false;
    }

    public int e(Enum r3) {
        j.f(r3, "element");
        int iOrdinal = r3.ordinal();
        if (((Enum) AbstractC0580h.s(this.f9675c, iOrdinal)) == r3) {
            return iOrdinal;
        }
        return -1;
    }

    public int f(Enum r22) {
        j.f(r22, "element");
        return indexOf(r22);
    }

    @Override // i2.AbstractC0574b, java.util.List
    public final /* bridge */ int indexOf(Object obj) {
        if (obj instanceof Enum) {
            return e((Enum) obj);
        }
        return -1;
    }

    @Override // i2.AbstractC0574b, java.util.List
    public final /* bridge */ int lastIndexOf(Object obj) {
        if (obj instanceof Enum) {
            return f((Enum) obj);
        }
        return -1;
    }
}
