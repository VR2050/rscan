package p403d.p410b;

import android.annotation.SuppressLint;
import android.util.Property;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p065a0.p066a.C1276a;

/* renamed from: d.b.b */
/* loaded from: classes.dex */
public abstract class AbstractC4198b<T> extends Property<T, Integer> {
    public AbstractC4198b(@Nullable String str) {
        super(Integer.class, str);
    }

    @Override // android.util.Property
    @SuppressLint({"NewApi"})
    public void set(@NonNull Object obj, @NonNull Integer num) {
        ((C1276a) this).f985a.mo304b(obj, num.intValue());
    }
}
