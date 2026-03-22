package kotlinx.coroutines;

import kotlin.coroutines.CoroutineContext;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public interface CoroutineExceptionHandler extends CoroutineContext.Element {

    /* renamed from: a */
    public static final /* synthetic */ int f12112a = 0;

    /* renamed from: kotlinx.coroutines.CoroutineExceptionHandler$a */
    public static final class C4735a implements CoroutineContext.Key<CoroutineExceptionHandler> {

        /* renamed from: a */
        public static final /* synthetic */ C4735a f12113a = new C4735a();
    }

    void handleException(@NotNull CoroutineContext coroutineContext, @NotNull Throwable th);
}
