package kotlin.reflect.jvm.internal.impl.load.java.typeEnhancement;

import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class EnhancementResult<T> {

    @Nullable
    private final Annotations enhancementAnnotations;
    private final T result;

    public EnhancementResult(T t, @Nullable Annotations annotations) {
        this.result = t;
        this.enhancementAnnotations = annotations;
    }

    public final T component1() {
        return this.result;
    }

    @Nullable
    public final Annotations component2() {
        return this.enhancementAnnotations;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof EnhancementResult)) {
            return false;
        }
        EnhancementResult enhancementResult = (EnhancementResult) obj;
        return Intrinsics.areEqual(this.result, enhancementResult.result) && Intrinsics.areEqual(this.enhancementAnnotations, enhancementResult.enhancementAnnotations);
    }

    public int hashCode() {
        T t = this.result;
        int hashCode = (t == null ? 0 : t.hashCode()) * 31;
        Annotations annotations = this.enhancementAnnotations;
        return hashCode + (annotations != null ? annotations.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("EnhancementResult(result=");
        m586H.append(this.result);
        m586H.append(", enhancementAnnotations=");
        m586H.append(this.enhancementAnnotations);
        m586H.append(')');
        return m586H.toString();
    }
}
