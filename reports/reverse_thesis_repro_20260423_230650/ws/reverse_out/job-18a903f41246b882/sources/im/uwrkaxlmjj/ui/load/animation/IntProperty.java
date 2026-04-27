package im.uwrkaxlmjj.ui.load.animation;

import android.util.Property;

/* JADX INFO: loaded from: classes5.dex */
public abstract class IntProperty<T> extends Property<T, Integer> {
    public abstract void setValue(T t, int i);

    public IntProperty(String name) {
        super(Integer.class, name);
    }

    @Override // android.util.Property
    public final void set(T object, Integer value) {
        setValue(object, value.intValue());
    }
}
