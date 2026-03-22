package kotlin.reflect.jvm.internal.impl.serialization.deserialization.builtins;

import java.io.InputStream;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class BuiltInsResourceLoader {
    @Nullable
    public final InputStream loadResource(@NotNull String path) {
        Intrinsics.checkNotNullParameter(path, "path");
        ClassLoader classLoader = BuiltInsResourceLoader.class.getClassLoader();
        InputStream resourceAsStream = classLoader == null ? null : classLoader.getResourceAsStream(path);
        return resourceAsStream == null ? ClassLoader.getSystemResourceAsStream(path) : resourceAsStream;
    }
}
