package im.uwrkaxlmjj.ui.load.animation;

import android.util.Property;

/* JADX INFO: loaded from: classes5.dex */
public abstract class FloatProperty<T> extends Property<T, Float> {
    public abstract void setValue(T t, float f);

    public FloatProperty(String name) {
        super(Float.class, name);
    }

    @Override // android.util.Property
    public final void set(T object, Float value) {
        setValue(object, value.floatValue());
    }
}
