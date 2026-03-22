package kotlin.reflect.jvm.internal.impl.types.checker;

import kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public interface NewTypeVariableConstructor {
    @Nullable
    TypeParameterDescriptor getOriginalTypeParameter();
}
