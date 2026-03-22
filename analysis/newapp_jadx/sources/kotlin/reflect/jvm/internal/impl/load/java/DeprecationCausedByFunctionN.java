package kotlin.reflect.jvm.internal.impl.load.java;

import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.DeclarationDescriptor;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class DeprecationCausedByFunctionN {

    @NotNull
    private final DeclarationDescriptor target;

    public DeprecationCausedByFunctionN(@NotNull DeclarationDescriptor target) {
        Intrinsics.checkNotNullParameter(target, "target");
        this.target = target;
    }
}
