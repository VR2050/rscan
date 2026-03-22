package p005b.p327w.p330b.p331b.p334e;

import androidx.lifecycle.LifecycleCoroutineScope;
import androidx.viewbinding.ViewBinding;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.w.b.b.e.i */
/* loaded from: classes2.dex */
public interface InterfaceC2846i {
    @Nullable
    ViewBinding getFailedBinding();

    void hideLoading();

    void loadingDialog();

    void loadingView();

    void onError(@NotNull Throwable th);

    void removeFailedView();

    @NotNull
    LifecycleCoroutineScope scope();

    void showFailedView();
}
