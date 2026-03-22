package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.Context;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.databinding.ActivityPersonalInfoBinding;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.p384n.C3024g;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\t\u0018\u0000 \u001a2\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0001\u001aB\u0007¢\u0006\u0004\b\u0019\u0010\nJ\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\f\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\u000e\u0010\nJ\u000f\u0010\u000f\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u000f\u0010\nJ\u000f\u0010\u0010\u001a\u00020\u0006H\u0014¢\u0006\u0004\b\u0010\u0010\nJ\u000f\u0010\u0011\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0011\u0010\nJ\u000f\u0010\u0013\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u0013\u0010\u0014R\u001d\u0010\u0018\u001a\u00020\u000b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\r¨\u0006\u001b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/MineInfoActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActivityPersonalInfoBinding;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;", "userInfo", "", "showUserInfo", "(Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;)V", "refreshUserInfo", "()V", "", "getCurrentSexy", "()I", "updateUserInfo", "initView", "onResume", "bindEvent", "", "getTopBarTitle", "()Ljava/lang/String;", "sexy$delegate", "Lkotlin/Lazy;", "getSexy", "sexy", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineInfoActivity extends BaseVMActivity<ActivityPersonalInfoBinding, MineViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: sexy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sexy = LazyKt__LazyJVMKt.lazy(new Function0<Integer>() { // from class: com.jbzd.media.movecartoons.ui.settings.MineInfoActivity$sexy$2
        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final int invoke2() {
            MyApp myApp = MyApp.f9891f;
            return MyApp.f9892g.sexy();
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Integer invoke() {
            return Integer.valueOf(invoke2());
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/MineInfoActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, MineInfoActivity.class);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final int getCurrentSexy() {
        if (((ActivityPersonalInfoBinding) getBodyBinding()).radioSexMale.isChecked()) {
            return 1;
        }
        return ((ActivityPersonalInfoBinding) getBodyBinding()).radioSexFemale.isChecked() ? 2 : 0;
    }

    private final int getSexy() {
        return ((Number) this.sexy.getValue()).intValue();
    }

    private final void refreshUserInfo() {
        C2354n.m2441W0(getViewModel().userInfoV2(), this, new Function1<UserInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.MineInfoActivity$refreshUserInfo$1
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
                MineInfoActivity.this.getViewModel().getUserInfo().setValue(MyApp.f9892g);
                MineInfoActivity.this.showUserInfo(lifecycleLoadingDialog);
            }
        }, false, null, 12);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public final void showUserInfo(UserInfoBean userInfo) {
        ((ActivityPersonalInfoBinding) getBodyBinding()).setUserInfo(userInfo);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public final void updateUserInfo() {
        String valueOf = String.valueOf(((ActivityPersonalInfoBinding) getBodyBinding()).editNickName.getText());
        boolean z = getCurrentSexy() != getSexy();
        InterfaceC3006b<Object> updateInfo = valueOf.length() > 0 ? getViewModel().updateInfo("nickname", valueOf) : null;
        InterfaceC3006b<Object> updateInfo2 = z ? getViewModel().updateInfo("sex", String.valueOf(getCurrentSexy())) : null;
        if (updateInfo == null && updateInfo2 == null) {
            return;
        }
        InterfaceC3006b<Object> c3024g = (updateInfo == null || updateInfo2 == null) ? updateInfo == null ? updateInfo2 : updateInfo : new C3024g(updateInfo2, updateInfo, new MineInfoActivity$updateUserInfo$request$1(null));
        if (c3024g == null) {
            return;
        }
        C2354n.m2441W0(c3024g, this, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.MineInfoActivity$updateUserInfo$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Object lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                C2354n.m2409L1(MineInfoActivity.this.getString(R.string.save_sccuess));
                MineViewModel.INSTANCE.getUserInfo();
                MineInfoActivity.this.finish();
            }
        }, false, null, 12);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        return "昵称设置";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        bodyBinding(new MineInfoActivity$initView$1(this));
        MyApp myApp = MyApp.f9891f;
        showUserInfo(MyApp.f9892g);
        viewModels(new MineInfoActivity$initView$2(this));
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        refreshUserInfo();
    }
}
