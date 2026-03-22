package com.jbzd.media.movecartoons.p396ui.share;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u000f\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\r\u0010\u0005\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0004R\u001f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00070\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000bR\u001f\u0010\r\u001a\b\u0012\u0004\u0012\u00020\f0\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\r\u0010\t\u001a\u0004\b\u000e\u0010\u000b¨\u0006\u0010"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/share/BindCodeViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "bindParent", "Landroidx/lifecycle/MutableLiveData;", "", "bindCode", "Landroidx/lifecycle/MutableLiveData;", "getBindCode", "()Landroidx/lifecycle/MutableLiveData;", "", "userInfoUpdateSuccess", "getUserInfoUpdateSuccess", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BindCodeViewModel extends BaseViewModel {

    @NotNull
    private final MutableLiveData<String> bindCode = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Boolean> userInfoUpdateSuccess = new MutableLiveData<>();

    public final void bindParent() {
        String code = this.bindCode.getValue();
        if (code == null) {
            return;
        }
        C0944a c0944a = new C0944a();
        Intrinsics.checkNotNullParameter(code, "code");
        C2354n.m2444X0(C2354n.m2465d0(c0944a.m287a().m249h(code), new BindCodeViewModel$bindParent$1(c0944a, null)), this, false, null, new Function1<UserInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.BindCodeViewModel$bindParent$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(UserInfoBean userInfoBean) {
                invoke2(userInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull UserInfoBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                MyApp myApp = MyApp.f9891f;
                MyApp.m4189j(lifecycleLoadingDialog);
                BindCodeViewModel.this.getUserInfoUpdateSuccess().setValue(Boolean.TRUE);
            }
        }, 6);
    }

    @NotNull
    public final MutableLiveData<String> getBindCode() {
        return this.bindCode;
    }

    @NotNull
    public final MutableLiveData<Boolean> getUserInfoUpdateSuccess() {
        return this.userInfoUpdateSuccess;
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }
}
