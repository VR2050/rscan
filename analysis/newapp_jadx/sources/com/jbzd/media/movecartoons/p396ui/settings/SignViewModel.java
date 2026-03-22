package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.Context;
import android.content.Intent;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\f\u0018\u0000 \u001b2\u00020\u0001:\u0001\u001bB\u0007¢\u0006\u0004\b\u001a\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u0015\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u0005¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\t\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u0005¢\u0006\u0004\b\t\u0010\bR\u001f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\n8\u0006@\u0006¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR\u001d\u0010\u0015\u001a\u00020\u00108B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014R\u001f\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u000b0\n8\u0006@\u0006¢\u0006\f\n\u0004\b\u0016\u0010\r\u001a\u0004\b\u0017\u0010\u000fR\u001f\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u000b0\n8\u0006@\u0006¢\u0006\f\n\u0004\b\u0018\u0010\r\u001a\u0004\b\u0019\u0010\u000f¨\u0006\u001c"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/SignViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "Landroid/content/Context;", "context", "register", "(Landroid/content/Context;)V", "refreshAccount", "Landroidx/lifecycle/MutableLiveData;", "", "inviteCode", "Landroidx/lifecycle/MutableLiveData;", "getInviteCode", "()Landroidx/lifecycle/MutableLiveData;", "Lb/a/a/a/r/n/a;", "repository$delegate", "Lkotlin/Lazy;", "getRepository", "()Lb/a/a/a/r/n/a;", "repository", "phoneData", "getPhoneData", "pwdData", "getPwdData", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SignViewModel extends BaseViewModel {

    @NotNull
    private static final String LOGIN = "login";

    @NotNull
    private static final String REGISTER = "register";

    /* renamed from: repository$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy repository = LazyKt__LazyJVMKt.lazy(new Function0<C0944a>() { // from class: com.jbzd.media.movecartoons.ui.settings.SignViewModel$repository$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0944a invoke() {
            return new C0944a();
        }
    });

    @NotNull
    private final MutableLiveData<String> phoneData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<String> pwdData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<String> inviteCode = new MutableLiveData<>();

    /* JADX INFO: Access modifiers changed from: private */
    public final C0944a getRepository() {
        return (C0944a) this.repository.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getInviteCode() {
        return this.inviteCode;
    }

    @NotNull
    public final MutableLiveData<String> getPhoneData() {
        return this.phoneData;
    }

    @NotNull
    public final MutableLiveData<String> getPwdData() {
        return this.pwdData;
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    public final void refreshAccount(@NotNull final Context context) {
        String pwd;
        Intrinsics.checkNotNullParameter(context, "context");
        String phone = this.phoneData.getValue();
        if (phone == null || (pwd = this.pwdData.getValue()) == null) {
            return;
        }
        String value = this.inviteCode.getValue();
        final String type = context instanceof LoginActivity ? LOGIN : "register";
        C0944a repository = getRepository();
        Objects.requireNonNull(repository);
        Intrinsics.checkNotNullParameter(phone, "phone");
        Intrinsics.checkNotNullParameter(pwd, "pwd");
        Intrinsics.checkNotNullParameter(type, "type");
        C2354n.m2444X0(C2354n.m2465d0(repository.m287a().m241K(phone, pwd, type, value), new SignViewModel$refreshAccount$1(this, null)), this, false, null, new Function1<UserInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.SignViewModel$refreshAccount$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                C2354n.m2409L1(context.getString(Intrinsics.areEqual(type, "login") ? R.string.login_success : R.string.sign_success));
                Context context2 = context;
                if (context2 instanceof AppCompatActivity) {
                    ((AppCompatActivity) context2).finish();
                }
            }
        }, 6);
    }

    public final void register(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (context instanceof LoginActivity) {
            context.startActivity(new Intent(context, (Class<?>) RegisterActivity.class));
            ((LoginActivity) context).finish();
        }
    }
}
