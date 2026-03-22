package p005b.p143g.p144a.p165p;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import p005b.p143g.p144a.p147m.InterfaceC1585q;

/* renamed from: b.g.a.p.f */
/* loaded from: classes.dex */
public class C1773f {

    /* renamed from: a */
    public final List<a<?>> f2650a = new ArrayList();

    /* renamed from: b.g.a.p.f$a */
    public static final class a<T> {

        /* renamed from: a */
        public final Class<T> f2651a;

        /* renamed from: b */
        public final InterfaceC1585q<T> f2652b;

        public a(@NonNull Class<T> cls, @NonNull InterfaceC1585q<T> interfaceC1585q) {
            this.f2651a = cls;
            this.f2652b = interfaceC1585q;
        }
    }

    @Nullable
    /* renamed from: a */
    public synchronized <Z> InterfaceC1585q<Z> m1069a(@NonNull Class<Z> cls) {
        int size = this.f2650a.size();
        for (int i2 = 0; i2 < size; i2++) {
            a<?> aVar = this.f2650a.get(i2);
            if (aVar.f2651a.isAssignableFrom(cls)) {
                return (InterfaceC1585q<Z>) aVar.f2652b;
            }
        }
        return null;
    }
}
