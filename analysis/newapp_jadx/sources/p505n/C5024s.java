package p505n;

import java.util.Iterator;
import javax.annotation.Nullable;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: n.s */
/* loaded from: classes3.dex */
public class C5024s<T> extends AbstractC5026u<Iterable<T>> {

    /* renamed from: a */
    public final /* synthetic */ AbstractC5026u f12857a;

    public C5024s(AbstractC5026u abstractC5026u) {
        this.f12857a = abstractC5026u;
    }

    @Override // p505n.AbstractC5026u
    /* renamed from: a */
    public void mo5674a(C5028w c5028w, @Nullable Object obj) {
        Iterable iterable = (Iterable) obj;
        if (iterable == null) {
            return;
        }
        Iterator<T> it = iterable.iterator();
        while (it.hasNext()) {
            this.f12857a.mo5674a(c5028w, it.next());
        }
    }
}
