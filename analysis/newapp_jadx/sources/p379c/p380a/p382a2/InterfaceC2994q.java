package p379c.p380a.p382a2;

import java.util.concurrent.CancellationException;
import kotlin.Deprecated;
import kotlin.DeprecationLevel;
import kotlin.ReplaceWith;
import kotlin.coroutines.Continuation;
import kotlin.internal.LowPriorityInOverloadResolution;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.a2.q */
/* loaded from: classes2.dex */
public interface InterfaceC2994q<E> {
    /* renamed from: c */
    boolean mo3457c();

    /* renamed from: d */
    void mo3458d(@Nullable CancellationException cancellationException);

    @Deprecated(level = DeprecationLevel.WARNING, message = "Deprecated in favor of receiveOrClosed and receiveOrNull extension", replaceWith = @ReplaceWith(expression = "receiveOrNull", imports = {"kotlinx.coroutines.channels.receiveOrNull"}))
    @LowPriorityInOverloadResolution
    @Nullable
    /* renamed from: e */
    Object mo3459e(@NotNull Continuation<? super E> continuation);

    @NotNull
    InterfaceC2984g<E> iterator();

    @Nullable
    /* renamed from: n */
    Object mo3460n(@NotNull Continuation<? super C3001x<? extends E>> continuation);
}
