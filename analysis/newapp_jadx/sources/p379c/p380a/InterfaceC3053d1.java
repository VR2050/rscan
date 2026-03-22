package p379c.p380a;

import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.CoroutineExceptionHandler;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.d1 */
/* loaded from: classes2.dex */
public interface InterfaceC3053d1 extends CoroutineContext.Element {

    /* renamed from: b */
    public static final a f8393b = a.f8394a;

    /* renamed from: c.a.d1$a */
    public static final class a implements CoroutineContext.Key<InterfaceC3053d1> {

        /* renamed from: a */
        public static final /* synthetic */ a f8394a = new a();

        static {
            int i2 = CoroutineExceptionHandler.f12112a;
        }
    }

    @NotNull
    /* renamed from: S */
    InterfaceC3081n mo3550S(@NotNull InterfaceC3087p interfaceC3087p);

    /* renamed from: b */
    boolean mo3507b();

    /* renamed from: d */
    void mo3551d(@Nullable CancellationException cancellationException);

    boolean isCancelled();

    @NotNull
    /* renamed from: o */
    InterfaceC3082n0 mo3552o(boolean z, boolean z2, @NotNull Function1<? super Throwable, Unit> function1);

    @NotNull
    /* renamed from: q */
    CancellationException mo3553q();

    boolean start();
}
