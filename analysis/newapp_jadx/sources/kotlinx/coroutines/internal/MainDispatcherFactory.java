package kotlinx.coroutines.internal;

import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.AbstractC3077l1;

/* loaded from: classes2.dex */
public interface MainDispatcherFactory {
    @NotNull
    AbstractC3077l1 createDispatcher(@NotNull List<? extends MainDispatcherFactory> list);

    int getLoadPriority();

    @Nullable
    String hintOnError();
}
