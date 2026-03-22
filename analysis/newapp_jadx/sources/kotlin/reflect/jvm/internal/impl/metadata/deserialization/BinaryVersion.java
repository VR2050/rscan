package kotlin.reflect.jvm.internal.impl.metadata.deserialization;

import java.util.ArrayList;
import java.util.List;
import kotlin.collections.ArraysKt___ArraysJvmKt;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public abstract class BinaryVersion {

    @NotNull
    public static final Companion Companion = new Companion(null);
    private final int major;
    private final int minor;

    @NotNull
    private final int[] numbers;
    private final int patch;

    @NotNull
    private final List<Integer> rest;

    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public BinaryVersion(@NotNull int... numbers) {
        Intrinsics.checkNotNullParameter(numbers, "numbers");
        this.numbers = numbers;
        Integer orNull = ArraysKt___ArraysKt.getOrNull(numbers, 0);
        this.major = orNull == null ? -1 : orNull.intValue();
        Integer orNull2 = ArraysKt___ArraysKt.getOrNull(numbers, 1);
        this.minor = orNull2 == null ? -1 : orNull2.intValue();
        Integer orNull3 = ArraysKt___ArraysKt.getOrNull(numbers, 2);
        this.patch = orNull3 != null ? orNull3.intValue() : -1;
        this.rest = numbers.length > 3 ? CollectionsKt___CollectionsKt.toList(ArraysKt___ArraysJvmKt.asList(numbers).subList(3, numbers.length)) : CollectionsKt__CollectionsKt.emptyList();
    }

    public boolean equals(@Nullable Object obj) {
        if (obj != null && Intrinsics.areEqual(getClass(), obj.getClass())) {
            BinaryVersion binaryVersion = (BinaryVersion) obj;
            if (this.major == binaryVersion.major && this.minor == binaryVersion.minor && this.patch == binaryVersion.patch && Intrinsics.areEqual(this.rest, binaryVersion.rest)) {
                return true;
            }
        }
        return false;
    }

    public final int getMajor() {
        return this.major;
    }

    public final int getMinor() {
        return this.minor;
    }

    public int hashCode() {
        int i2 = this.major;
        int i3 = (i2 * 31) + this.minor + i2;
        int i4 = (i3 * 31) + this.patch + i3;
        return this.rest.hashCode() + (i4 * 31) + i4;
    }

    public final boolean isAtLeast(@NotNull BinaryVersion version) {
        Intrinsics.checkNotNullParameter(version, "version");
        return isAtLeast(version.major, version.minor, version.patch);
    }

    public final boolean isAtMost(int i2, int i3, int i4) {
        int i5 = this.major;
        if (i5 < i2) {
            return true;
        }
        if (i5 > i2) {
            return false;
        }
        int i6 = this.minor;
        if (i6 < i3) {
            return true;
        }
        return i6 <= i3 && this.patch <= i4;
    }

    public final boolean isCompatibleTo(@NotNull BinaryVersion ourVersion) {
        Intrinsics.checkNotNullParameter(ourVersion, "ourVersion");
        int i2 = this.major;
        if (i2 == 0) {
            if (ourVersion.major == 0 && this.minor == ourVersion.minor) {
                return true;
            }
        } else if (i2 == ourVersion.major && this.minor <= ourVersion.minor) {
            return true;
        }
        return false;
    }

    @NotNull
    public final int[] toArray() {
        return this.numbers;
    }

    @NotNull
    public String toString() {
        int[] array = toArray();
        ArrayList arrayList = new ArrayList();
        int length = array.length;
        for (int i2 = 0; i2 < length; i2++) {
            int i3 = array[i2];
            if (!(i3 != -1)) {
                break;
            }
            arrayList.add(Integer.valueOf(i3));
        }
        return arrayList.isEmpty() ? "unknown" : CollectionsKt___CollectionsKt.joinToString$default(arrayList, ".", null, null, 0, null, null, 62, null);
    }

    public final boolean isAtLeast(int i2, int i3, int i4) {
        int i5 = this.major;
        if (i5 > i2) {
            return true;
        }
        if (i5 < i2) {
            return false;
        }
        int i6 = this.minor;
        if (i6 > i3) {
            return true;
        }
        return i6 >= i3 && this.patch >= i4;
    }
}
