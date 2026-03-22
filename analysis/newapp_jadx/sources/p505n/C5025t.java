package p505n;

import java.lang.reflect.Array;
import javax.annotation.Nullable;

/* renamed from: n.t */
/* loaded from: classes3.dex */
public class C5025t extends AbstractC5026u<Object> {

    /* renamed from: a */
    public final /* synthetic */ AbstractC5026u f12858a;

    public C5025t(AbstractC5026u abstractC5026u) {
        this.f12858a = abstractC5026u;
    }

    @Override // p505n.AbstractC5026u
    /* renamed from: a */
    public void mo5674a(C5028w c5028w, @Nullable Object obj) {
        if (obj == null) {
            return;
        }
        int length = Array.getLength(obj);
        for (int i2 = 0; i2 < length; i2++) {
            this.f12858a.mo5674a(c5028w, Array.get(obj, i2));
        }
    }
}
