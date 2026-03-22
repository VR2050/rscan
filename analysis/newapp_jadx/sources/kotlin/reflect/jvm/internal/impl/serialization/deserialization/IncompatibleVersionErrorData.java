package kotlin.reflect.jvm.internal.impl.serialization.deserialization;

import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.name.ClassId;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class IncompatibleVersionErrorData<T> {
    private final T actualVersion;

    @NotNull
    private final ClassId classId;
    private final T expectedVersion;

    @NotNull
    private final String filePath;

    public IncompatibleVersionErrorData(T t, T t2, @NotNull String filePath, @NotNull ClassId classId) {
        Intrinsics.checkNotNullParameter(filePath, "filePath");
        Intrinsics.checkNotNullParameter(classId, "classId");
        this.actualVersion = t;
        this.expectedVersion = t2;
        this.filePath = filePath;
        this.classId = classId;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof IncompatibleVersionErrorData)) {
            return false;
        }
        IncompatibleVersionErrorData incompatibleVersionErrorData = (IncompatibleVersionErrorData) obj;
        return Intrinsics.areEqual(this.actualVersion, incompatibleVersionErrorData.actualVersion) && Intrinsics.areEqual(this.expectedVersion, incompatibleVersionErrorData.expectedVersion) && Intrinsics.areEqual(this.filePath, incompatibleVersionErrorData.filePath) && Intrinsics.areEqual(this.classId, incompatibleVersionErrorData.classId);
    }

    public int hashCode() {
        T t = this.actualVersion;
        int hashCode = (t == null ? 0 : t.hashCode()) * 31;
        T t2 = this.expectedVersion;
        return this.classId.hashCode() + C1499a.m598T(this.filePath, (hashCode + (t2 != null ? t2.hashCode() : 0)) * 31, 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("IncompatibleVersionErrorData(actualVersion=");
        m586H.append(this.actualVersion);
        m586H.append(", expectedVersion=");
        m586H.append(this.expectedVersion);
        m586H.append(", filePath=");
        m586H.append(this.filePath);
        m586H.append(", classId=");
        m586H.append(this.classId);
        m586H.append(')');
        return m586H.toString();
    }
}
