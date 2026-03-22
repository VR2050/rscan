package androidx.camera.core.impl.utils;

import androidx.annotation.Nullable;
import androidx.core.util.Preconditions;
import androidx.core.util.Supplier;

/* loaded from: classes.dex */
public final class Absent<T> extends Optional<T> {
    public static final Absent<Object> sInstance = new Absent<>();
    private static final long serialVersionUID = 0;

    private Absent() {
    }

    private Object readResolve() {
        return sInstance;
    }

    public static <T> Optional<T> withType() {
        return sInstance;
    }

    @Override // androidx.camera.core.impl.utils.Optional
    public boolean equals(@Nullable Object obj) {
        return obj == this;
    }

    @Override // androidx.camera.core.impl.utils.Optional
    public T get() {
        throw new IllegalStateException("Optional.get() cannot be called on an absent value");
    }

    @Override // androidx.camera.core.impl.utils.Optional
    public int hashCode() {
        return 2040732332;
    }

    @Override // androidx.camera.core.impl.utils.Optional
    public boolean isPresent() {
        return false;
    }

    @Override // androidx.camera.core.impl.utils.Optional
    /* renamed from: or */
    public T mo143or(T t) {
        return (T) Preconditions.checkNotNull(t, "use Optional.orNull() instead of Optional.or(null)");
    }

    @Override // androidx.camera.core.impl.utils.Optional
    @Nullable
    public T orNull() {
        return null;
    }

    @Override // androidx.camera.core.impl.utils.Optional
    public String toString() {
        return "Optional.absent()";
    }

    @Override // androidx.camera.core.impl.utils.Optional
    /* renamed from: or */
    public Optional<T> mo141or(Optional<? extends T> optional) {
        return (Optional) Preconditions.checkNotNull(optional);
    }

    @Override // androidx.camera.core.impl.utils.Optional
    /* renamed from: or */
    public T mo142or(Supplier<? extends T> supplier) {
        return (T) Preconditions.checkNotNull(supplier.get(), "use Optional.orNull() instead of a Supplier that returns null");
    }
}
