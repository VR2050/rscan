package com.jbzd.media.movecartoons.p396ui.vip;

import androidx.lifecycle.MutableLiveData;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0012\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\r\u0010\u0005\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0004R\u001f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00070\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000bR\u001d\u0010\u0011\u001a\u00020\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010¨\u0006\u0013"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/ExchangeViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "exchangeVip", "Landroidx/lifecycle/MutableLiveData;", "", "exchangeCode", "Landroidx/lifecycle/MutableLiveData;", "getExchangeCode", "()Landroidx/lifecycle/MutableLiveData;", "Lb/a/a/a/r/n/a;", "repository$delegate", "Lkotlin/Lazy;", "getRepository", "()Lb/a/a/a/r/n/a;", "repository", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ExchangeViewModel extends BaseViewModel {

    /* renamed from: repository$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy repository = LazyKt__LazyJVMKt.lazy(new Function0<C0944a>() { // from class: com.jbzd.media.movecartoons.ui.vip.ExchangeViewModel$repository$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0944a invoke() {
            return new C0944a();
        }
    });

    @NotNull
    private final MutableLiveData<String> exchangeCode = new MutableLiveData<>();

    public final void exchangeVip() {
        String value = this.exchangeCode.getValue();
        String code = value == null ? null : StringsKt__StringsKt.trim((CharSequence) value).toString();
        if (code == null) {
            return;
        }
        C0944a repository = getRepository();
        Objects.requireNonNull(repository);
        Intrinsics.checkNotNullParameter(code, "code");
        C2354n.m2444X0(repository.m287a().m246e(code), this, false, null, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.ExchangeViewModel$exchangeVip$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull String lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
            }
        }, 6);
    }

    @NotNull
    public final MutableLiveData<String> getExchangeCode() {
        return this.exchangeCode;
    }

    @NotNull
    public final C0944a getRepository() {
        return (C0944a) this.repository.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }
}
