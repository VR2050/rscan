package p005b.p065a0.p066a;

import android.annotation.TargetApi;
import android.util.Property;
import androidx.annotation.NonNull;

@TargetApi(14)
/* renamed from: b.a0.a.b */
/* loaded from: classes2.dex */
public abstract class AbstractC1277b<T> extends Property<T, Integer> {
    public AbstractC1277b() {
        super(Integer.class, null);
    }

    @NonNull
    /* renamed from: a */
    public abstract Integer mo303a(T t);

    /* renamed from: b */
    public abstract void mo304b(@NonNull T t, int i2);

    /* JADX WARN: Multi-variable type inference failed */
    @Override // android.util.Property
    public void set(@NonNull Object obj, @NonNull Integer num) {
        mo304b(obj, num.intValue());
    }
}
