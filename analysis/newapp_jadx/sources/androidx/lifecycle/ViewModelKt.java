package androidx.lifecycle;

import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.AbstractC3036c0;
import p379c.p380a.C3079m0;
import p379c.p380a.C3101t1;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0003\"\u0017\u0010\u0004\u001a\u00020\u0001*\u00020\u00008F@\u0006¢\u0006\u0006\u001a\u0004\b\u0002\u0010\u0003\"\u0016\u0010\u0006\u001a\u00020\u00058\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0006\u0010\u0007¨\u0006\b"}, m5311d2 = {"Landroidx/lifecycle/ViewModel;", "Lc/a/e0;", "getViewModelScope", "(Landroidx/lifecycle/ViewModel;)Lc/a/e0;", "viewModelScope", "", "JOB_KEY", "Ljava/lang/String;", "lifecycle-viewmodel-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class ViewModelKt {
    private static final String JOB_KEY = "androidx.lifecycle.ViewModelCoroutineScope.JOB_KEY";

    @NotNull
    public static final InterfaceC3055e0 getViewModelScope(@NotNull ViewModel viewModelScope) {
        Intrinsics.checkParameterIsNotNull(viewModelScope, "$this$viewModelScope");
        InterfaceC3055e0 interfaceC3055e0 = (InterfaceC3055e0) viewModelScope.getTag(JOB_KEY);
        if (interfaceC3055e0 != null) {
            return interfaceC3055e0;
        }
        C3101t1 c3101t1 = new C3101t1(null);
        AbstractC3036c0 abstractC3036c0 = C3079m0.f8430a;
        Object tagIfAbsent = viewModelScope.setTagIfAbsent(JOB_KEY, new CloseableCoroutineScope(CoroutineContext.Element.DefaultImpls.plus(c3101t1, C2964m.f8127b.mo3620U())));
        Intrinsics.checkExpressionValueIsNotNull(tagIfAbsent, "setTagIfAbsent(JOB_KEY,\n…patchers.Main.immediate))");
        return (InterfaceC3055e0) tagIfAbsent;
    }
}
