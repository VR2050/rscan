package p005b.p143g.p144a.p147m;

import android.content.Context;
import androidx.annotation.NonNull;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

/* renamed from: b.g.a.m.l */
/* loaded from: classes.dex */
public class C1580l<T> implements InterfaceC1586r<T> {

    /* renamed from: b */
    public final Collection<? extends InterfaceC1586r<T>> f1989b;

    @SafeVarargs
    public C1580l(@NonNull InterfaceC1586r<T>... interfaceC1586rArr) {
        if (interfaceC1586rArr.length == 0) {
            throw new IllegalArgumentException("MultiTransformation must contain at least one Transformation");
        }
        this.f1989b = Arrays.asList(interfaceC1586rArr);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (obj instanceof C1580l) {
            return this.f1989b.equals(((C1580l) obj).f1989b);
        }
        return false;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return this.f1989b.hashCode();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1586r
    @NonNull
    public InterfaceC1655w<T> transform(@NonNull Context context, @NonNull InterfaceC1655w<T> interfaceC1655w, int i2, int i3) {
        Iterator<? extends InterfaceC1586r<T>> it = this.f1989b.iterator();
        InterfaceC1655w<T> interfaceC1655w2 = interfaceC1655w;
        while (it.hasNext()) {
            InterfaceC1655w<T> transform = it.next().transform(context, interfaceC1655w2, i2, i3);
            if (interfaceC1655w2 != null && !interfaceC1655w2.equals(interfaceC1655w) && !interfaceC1655w2.equals(transform)) {
                interfaceC1655w2.recycle();
            }
            interfaceC1655w2 = transform;
        }
        return interfaceC1655w2;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        Iterator<? extends InterfaceC1586r<T>> it = this.f1989b.iterator();
        while (it.hasNext()) {
            it.next().updateDiskCacheKey(messageDigest);
        }
    }
}
