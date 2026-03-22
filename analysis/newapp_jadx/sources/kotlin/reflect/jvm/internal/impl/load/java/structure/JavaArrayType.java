package kotlin.reflect.jvm.internal.impl.load.java.structure;

import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public interface JavaArrayType extends JavaType {
    @NotNull
    JavaType getComponentType();
}
