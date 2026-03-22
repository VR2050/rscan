package androidx.camera.core.impl.utils;

import androidx.annotation.Nullable;
import androidx.core.util.Preconditions;
import androidx.core.util.Supplier;
import java.io.Serializable;

/* loaded from: classes.dex */
public abstract class Optional<T> implements Serializable {
    private static final long serialVersionUID = 0;

    public static <T> Optional<T> absent() {
        return Absent.withType();
    }

    public static <T> Optional<T> fromNullable(@Nullable T t) {
        return t == null ? absent() : new Present(t);
    }

    /* renamed from: of */
    public static <T> Optional<T> m144of(T t) {
        return new Present(Preconditions.checkNotNull(t));
    }

    public abstract boolean equals(@Nullable Object obj);

    public abstract T get();

    public abstract int hashCode();

    public abstract boolean isPresent();

    /* renamed from: or */
    public abstract Optional<T> mo141or(Optional<? extends T> optional);

    /* renamed from: or */
    public abstract T mo142or(Supplier<? extends T> supplier);

    /* renamed from: or */
    public abstract T mo143or(T t);

    @Nullable
    public abstract T orNull();

    public abstract String toString();
}
