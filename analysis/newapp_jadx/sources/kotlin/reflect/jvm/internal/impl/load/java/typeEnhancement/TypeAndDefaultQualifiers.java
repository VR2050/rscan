package kotlin.reflect.jvm.internal.impl.load.java.typeEnhancement;

import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor;
import kotlin.reflect.jvm.internal.impl.load.java.JavaDefaultQualifiers;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class TypeAndDefaultQualifiers {

    @Nullable
    private final JavaDefaultQualifiers defaultQualifiers;
    private final boolean isFromStarProjection;

    @NotNull
    private final KotlinType type;

    @Nullable
    private final TypeParameterDescriptor typeParameterForArgument;

    public TypeAndDefaultQualifiers(@NotNull KotlinType type, @Nullable JavaDefaultQualifiers javaDefaultQualifiers, @Nullable TypeParameterDescriptor typeParameterDescriptor, boolean z) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.type = type;
        this.defaultQualifiers = javaDefaultQualifiers;
        this.typeParameterForArgument = typeParameterDescriptor;
        this.isFromStarProjection = z;
    }

    @NotNull
    public final KotlinType component1() {
        return this.type;
    }

    @Nullable
    public final JavaDefaultQualifiers component2() {
        return this.defaultQualifiers;
    }

    @Nullable
    public final TypeParameterDescriptor component3() {
        return this.typeParameterForArgument;
    }

    public final boolean component4() {
        return this.isFromStarProjection;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TypeAndDefaultQualifiers)) {
            return false;
        }
        TypeAndDefaultQualifiers typeAndDefaultQualifiers = (TypeAndDefaultQualifiers) obj;
        return Intrinsics.areEqual(this.type, typeAndDefaultQualifiers.type) && Intrinsics.areEqual(this.defaultQualifiers, typeAndDefaultQualifiers.defaultQualifiers) && Intrinsics.areEqual(this.typeParameterForArgument, typeAndDefaultQualifiers.typeParameterForArgument) && this.isFromStarProjection == typeAndDefaultQualifiers.isFromStarProjection;
    }

    @NotNull
    public final KotlinType getType() {
        return this.type;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int hashCode() {
        int hashCode = this.type.hashCode() * 31;
        JavaDefaultQualifiers javaDefaultQualifiers = this.defaultQualifiers;
        int hashCode2 = (hashCode + (javaDefaultQualifiers == null ? 0 : javaDefaultQualifiers.hashCode())) * 31;
        TypeParameterDescriptor typeParameterDescriptor = this.typeParameterForArgument;
        int hashCode3 = (hashCode2 + (typeParameterDescriptor != null ? typeParameterDescriptor.hashCode() : 0)) * 31;
        boolean z = this.isFromStarProjection;
        int i2 = z;
        if (z != 0) {
            i2 = 1;
        }
        return hashCode3 + i2;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("TypeAndDefaultQualifiers(type=");
        m586H.append(this.type);
        m586H.append(", defaultQualifiers=");
        m586H.append(this.defaultQualifiers);
        m586H.append(", typeParameterForArgument=");
        m586H.append(this.typeParameterForArgument);
        m586H.append(", isFromStarProjection=");
        m586H.append(this.isFromStarProjection);
        m586H.append(')');
        return m586H.toString();
    }
}
