package com.jbzd.media.movecartoons.p396ui.settings;

import android.text.Editable;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModelKt;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.bean.response.PicVefBean;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
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
import p005b.p006a.p007a.p008a.p009a.p011p0.C0868b;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p333d.C2833b;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;
import p379c.p380a.p383b2.InterfaceC3006b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b\t\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b/\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u0015\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u0005¢\u0006\u0004\b\u0007\u0010\bJ\r\u0010\t\u001a\u00020\u0002¢\u0006\u0004\b\t\u0010\u0004J\r\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b\n\u0010\u0004J\r\u0010\u000b\u001a\u00020\u0002¢\u0006\u0004\b\u000b\u0010\u0004R#\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\r0\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0017\u001a\u00020\u00138B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u000f\u001a\u0004\b\u0015\u0010\u0016R#\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00180\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u000f\u001a\u0004\b\u001a\u0010\u0011R#\u0010\u001e\u001a\b\u0012\u0004\u0012\u00020\r0\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u000f\u001a\u0004\b\u001d\u0010\u0011R#\u0010!\u001a\b\u0012\u0004\u0012\u00020\u00180\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u000f\u001a\u0004\b \u0010\u0011R#\u0010$\u001a\b\u0012\u0004\u0012\u00020\r0\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u000f\u001a\u0004\b#\u0010\u0011R#\u0010&\u001a\b\u0012\u0004\u0012\u00020\u00180\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u000f\u001a\u0004\b&\u0010\u0011R\u001d\u0010+\u001a\u00020'8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u000f\u001a\u0004\b)\u0010*R#\u0010.\u001a\b\u0012\u0004\u0012\u00020\r0\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u000f\u001a\u0004\b-\u0010\u0011¨\u00060"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/PhoneViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "Landroid/text/Editable;", "s", "formatPhone", "(Landroid/text/Editable;)V", "submit", "getPicCaptcha", "updateUserInfo", "Landroidx/lifecycle/MutableLiveData;", "", "picCode$delegate", "Lkotlin/Lazy;", "getPicCode", "()Landroidx/lifecycle/MutableLiveData;", "picCode", "Lb/a/a/a/a/p0/b;", "phoneTextChanger$delegate", "getPhoneTextChanger", "()Lb/a/a/a/a/p0/b;", "phoneTextChanger", "", "findByPhoneSuccess$delegate", "getFindByPhoneSuccess", "findByPhoneSuccess", "picBean$delegate", "getPicBean", "picBean", "bindPhoneSuccess$delegate", "getBindPhoneSuccess", "bindPhoneSuccess", "smsCode$delegate", "getSmsCode", "smsCode", "isBinding$delegate", "isBinding", "Lb/a/a/a/r/n/a;", "repository$delegate", "getRepository", "()Lb/a/a/a/r/n/a;", "repository", "phoneNumData$delegate", "getPhoneNumData", "phoneNumData", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PhoneViewModel extends BaseViewModel {

    /* renamed from: repository$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy repository = LazyKt__LazyJVMKt.lazy(new Function0<C0944a>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$repository$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0944a invoke() {
            return new C0944a();
        }
    });

    /* renamed from: phoneNumData$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy phoneNumData = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$phoneNumData$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: smsCode$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy smsCode = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$smsCode$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: picCode$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy picCode = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$picCode$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: picBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy picBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$picBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: isBinding$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy isBinding = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$isBinding$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: findByPhoneSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy findByPhoneSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$findByPhoneSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: bindPhoneSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bindPhoneSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$bindPhoneSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: phoneTextChanger$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy phoneTextChanger = LazyKt__LazyJVMKt.lazy(new Function0<C0868b>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$phoneTextChanger$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0868b invoke() {
            return new C0868b();
        }
    });

    private final C0868b getPhoneTextChanger() {
        return (C0868b) this.phoneTextChanger.getValue();
    }

    private final C0944a getRepository() {
        return (C0944a) this.repository.getValue();
    }

    public final void formatPhone(@NotNull Editable s) {
        Intrinsics.checkNotNullParameter(s, "s");
        getPhoneTextChanger().afterTextChanged(s);
    }

    @NotNull
    public final MutableLiveData<Boolean> getBindPhoneSuccess() {
        return (MutableLiveData) this.bindPhoneSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getFindByPhoneSuccess() {
        return (MutableLiveData) this.findByPhoneSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getPhoneNumData() {
        return (MutableLiveData) this.phoneNumData.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getPicBean() {
        return (MutableLiveData) this.picBean.getValue();
    }

    public final void getPicCaptcha() {
        C2354n.m2444X0(getRepository().m287a().m236F(), this, false, null, new Function1<PicVefBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$getPicCaptcha$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PicVefBean picVefBean) {
                invoke2(picVefBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull PicVefBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                PhoneViewModel.this.getPicBean().setValue(lifecycleLoadingDialog.getBase64WithoutHead());
            }
        }, 6);
    }

    @NotNull
    public final MutableLiveData<String> getPicCode() {
        return (MutableLiveData) this.picCode.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getSmsCode() {
        return (MutableLiveData) this.smsCode.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> isBinding() {
        return (MutableLiveData) this.isBinding.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    public final void submit() {
        String phone;
        String obj;
        String value = getPhoneNumData().getValue();
        String code = "";
        if (value == null || (phone = StringsKt__StringsKt.trim((CharSequence) value).toString()) == null) {
            phone = "";
        }
        String value2 = getSmsCode().getValue();
        if (value2 != null && (obj = StringsKt__StringsKt.trim((CharSequence) value2).toString()) != null) {
            code = obj;
        }
        if (Intrinsics.areEqual(isBinding().getValue(), Boolean.FALSE)) {
            C0944a repository = getRepository();
            Objects.requireNonNull(repository);
            Intrinsics.checkNotNullParameter(phone, "phone");
            Intrinsics.checkNotNullParameter(code, "code");
            C2354n.m2444X0(repository.m287a().m242a(phone, code), this, false, null, new Function1<TokenBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$submit$1
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TokenBean tokenBean) {
                    invoke2(tokenBean);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull TokenBean lifecycleLoadingDialog) {
                    Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                    MyApp myApp = MyApp.f9891f;
                    MyApp.m4188i(lifecycleLoadingDialog);
                    PhoneViewModel.this.getFindByPhoneSuccess().setValue(Boolean.TRUE);
                }
            }, 6);
            return;
        }
        C0944a repository2 = getRepository();
        Objects.requireNonNull(repository2);
        Intrinsics.checkNotNullParameter(phone, "phone");
        Intrinsics.checkNotNullParameter(code, "code");
        C2354n.m2444X0(repository2.m287a().m255n(phone, code), this, false, null, new Function1<TokenBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$submit$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TokenBean tokenBean) {
                invoke2(tokenBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TokenBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                MyApp myApp = MyApp.f9891f;
                MyApp.m4188i(lifecycleLoadingDialog);
                PhoneViewModel.this.getBindPhoneSuccess().setValue(Boolean.TRUE);
            }
        }, 6);
    }

    public final void updateUserInfo() {
        InterfaceC3006b<UserInfoBean> m288b = getRepository().m288b();
        PhoneViewModel$updateUserInfo$1 callback = new Function1<UserInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.PhoneViewModel$updateUserInfo$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(UserInfoBean userInfoBean) {
                invoke2(userInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull UserInfoBean lifecycle) {
                Intrinsics.checkNotNullParameter(lifecycle, "$this$lifecycle");
                MyApp myApp = MyApp.f9891f;
                MyApp.m4189j(lifecycle);
            }
        };
        Intrinsics.checkNotNullParameter(m288b, "<this>");
        Intrinsics.checkNotNullParameter(this, "baseViewModel");
        Intrinsics.checkNotNullParameter(callback, "callback");
        InterfaceC3055e0 viewModelScope = ViewModelKt.getViewModelScope(this);
        C3079m0 c3079m0 = C3079m0.f8432c;
        C2354n.m2435U0(viewModelScope, C2964m.f8127b, 0, new C2833b(m288b, this, false, null, callback, null), 2, null);
    }
}
