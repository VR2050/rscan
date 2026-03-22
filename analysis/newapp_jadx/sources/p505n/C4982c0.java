package p505n;

import java.lang.annotation.Annotation;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: n.c0 */
/* loaded from: classes3.dex */
public final class C4982c0 implements InterfaceC4980b0 {

    /* renamed from: a */
    public static final InterfaceC4980b0 f12806a = new C4982c0();

    @Override // java.lang.annotation.Annotation
    public Class<? extends Annotation> annotationType() {
        return InterfaceC4980b0.class;
    }

    @Override // java.lang.annotation.Annotation
    public boolean equals(Object obj) {
        return obj instanceof InterfaceC4980b0;
    }

    @Override // java.lang.annotation.Annotation
    public int hashCode() {
        return 0;
    }

    @Override // java.lang.annotation.Annotation
    public String toString() {
        StringBuilder m586H = C1499a.m586H("@");
        m586H.append(InterfaceC4980b0.class.getName());
        m586H.append("()");
        return m586H.toString();
    }
}
