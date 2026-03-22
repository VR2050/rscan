package p005b.p143g.p144a;

import p005b.p143g.p144a.AbstractC1560j;

/* renamed from: b.g.a.j */
/* loaded from: classes.dex */
public abstract class AbstractC1560j<CHILD extends AbstractC1560j<CHILD, TranscodeType>, TranscodeType> implements Cloneable {
    /* renamed from: a */
    public final CHILD m781a() {
        try {
            return (CHILD) super.clone();
        } catch (CloneNotSupportedException e2) {
            throw new RuntimeException(e2);
        }
    }

    public Object clone() {
        try {
            return (AbstractC1560j) super.clone();
        } catch (CloneNotSupportedException e2) {
            throw new RuntimeException(e2);
        }
    }
}
