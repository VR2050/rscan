package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import androidx.activity.ComponentActivity;
import androidx.appcompat.widget.AppCompatButton;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.p396ui.settings.UserInfoSexActivity;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p258c.C2480j;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000B\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u0000 *2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001*B\u0007¢\u0006\u0004\b)\u0010\u0010J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0017\u0010\t\u001a\u00020\b2\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\t\u0010\nJ\u0019\u0010\r\u001a\u00020\b2\b\u0010\f\u001a\u0004\u0018\u00010\u000bH\u0014¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\bH\u0014¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\bH\u0016¢\u0006\u0004\b\u0011\u0010\u0010J\u000f\u0010\u0012\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0012\u0010\u0005J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\r\u0010\u0016\u001a\u00020\u0002¢\u0006\u0004\b\u0016\u0010\u0017R\u001d\u0010\u001d\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\u001d\u0010\"\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u001a\u001a\u0004\b \u0010!R\u001d\u0010%\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u001a\u001a\u0004\b$\u0010\u0017R\u001d\u0010(\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u001a\u001a\u0004\b'\u0010\u001c¨\u0006+"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/UserInfoSexActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "", "getCurrentSexy", "()I", "Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;", "userInfo", "", "initView", "(Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "onResume", "()V", "bindEvent", "getLayoutId", "", "getTopBarTitle", "()Ljava/lang/String;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "Landroid/widget/CheckBox;", "radio_sex_female$delegate", "Lkotlin/Lazy;", "getRadio_sex_female", "()Landroid/widget/CheckBox;", "radio_sex_female", "Landroidx/appcompat/widget/AppCompatButton;", "btn_submit$delegate", "getBtn_submit", "()Landroidx/appcompat/widget/AppCompatButton;", "btn_submit", "viewModel$delegate", "getViewModel", "viewModel", "radio_sex_male$delegate", "getRadio_sex_male", "radio_sex_male", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class UserInfoSexActivity extends MyThemeActivity<MineViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: radio_sex_female$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy radio_sex_female = LazyKt__LazyJVMKt.lazy(new Function0<CheckBox>() { // from class: com.jbzd.media.movecartoons.ui.settings.UserInfoSexActivity$radio_sex_female$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CheckBox invoke() {
            CheckBox checkBox = (CheckBox) UserInfoSexActivity.this.findViewById(R.id.radio_sex_female);
            Intrinsics.checkNotNull(checkBox);
            return checkBox;
        }
    });

    /* renamed from: radio_sex_male$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy radio_sex_male = LazyKt__LazyJVMKt.lazy(new Function0<CheckBox>() { // from class: com.jbzd.media.movecartoons.ui.settings.UserInfoSexActivity$radio_sex_male$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CheckBox invoke() {
            CheckBox checkBox = (CheckBox) UserInfoSexActivity.this.findViewById(R.id.radio_sex_male);
            Intrinsics.checkNotNull(checkBox);
            return checkBox;
        }
    });

    /* renamed from: btn_submit$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_submit = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatButton>() { // from class: com.jbzd.media.movecartoons.ui.settings.UserInfoSexActivity$btn_submit$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatButton invoke() {
            AppCompatButton appCompatButton = (AppCompatButton) UserInfoSexActivity.this.findViewById(R.id.btn_submit);
            Intrinsics.checkNotNull(appCompatButton);
            return appCompatButton;
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(MineViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.settings.UserInfoSexActivity$special$$inlined$viewModels$default$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelStore invoke() {
            ViewModelStore viewModelStore = ComponentActivity.this.getViewModelStore();
            Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "viewModelStore");
            return viewModelStore;
        }
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.settings.UserInfoSexActivity$special$$inlined$viewModels$default$1
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelProvider.Factory invoke() {
            ViewModelProvider.Factory defaultViewModelProviderFactory = ComponentActivity.this.getDefaultViewModelProviderFactory();
            Intrinsics.checkExpressionValueIsNotNull(defaultViewModelProviderFactory, "defaultViewModelProviderFactory");
            return defaultViewModelProviderFactory;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/UserInfoSexActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, UserInfoSexActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-2, reason: not valid java name */
    public static final void m6000bindEvent$lambda6$lambda2(MineViewModel this_run, UserInfoSexActivity this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        MineViewModel.requestUserInfo$default(this_run, false, false, 3, null);
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (it.booleanValue()) {
            C2354n.m2409L1("修改成功");
            this$0.finish();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-3, reason: not valid java name */
    public static final void m6001bindEvent$lambda6$lambda3(UserInfoSexActivity this$0, UserInfoBean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        this$0.initView(it);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-4, reason: not valid java name */
    public static final void m6002bindEvent$lambda6$lambda4(UserInfoSexActivity this$0, CompoundButton compoundButton, boolean z) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (z && this$0.getRadio_sex_male().isChecked()) {
            this$0.getRadio_sex_male().setChecked(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-5, reason: not valid java name */
    public static final void m6003bindEvent$lambda6$lambda5(UserInfoSexActivity this$0, CompoundButton compoundButton, boolean z) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (z && this$0.getRadio_sex_female().isChecked()) {
            this$0.getRadio_sex_female().setChecked(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int getCurrentSexy() {
        if (getRadio_sex_male().isChecked()) {
            return 1;
        }
        return getRadio_sex_female().isChecked() ? 2 : 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MineViewModel getViewModel() {
        return (MineViewModel) this.viewModel.getValue();
    }

    private final void initView(UserInfoBean userInfo) {
        Intrinsics.stringPlus("AAAAA用户性别==", new C2480j().m2853g(userInfo));
        StackTraceElement stackTraceElement = Thread.currentThread().getStackTrace()[4];
        String className = stackTraceElement.getClassName();
        String.format("%s.%s(L:%d)", className.substring(className.lastIndexOf(".") + 1), stackTraceElement.getMethodName(), Integer.valueOf(stackTraceElement.getLineNumber()));
        TextUtils.isEmpty("");
        getRadio_sex_male().setChecked(userInfo.sexy() == 1);
        getRadio_sex_female().setChecked(userInfo.sexy() == 2);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        final MineViewModel viewModel = getViewModel();
        viewModel.getUserInfoUpdateSuccess().observe(this, new Observer() { // from class: b.a.a.a.t.n.f
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                UserInfoSexActivity.m6000bindEvent$lambda6$lambda2(MineViewModel.this, this, (Boolean) obj);
            }
        });
        viewModel.getUserInfo().observe(this, new Observer() { // from class: b.a.a.a.t.n.g
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                UserInfoSexActivity.m6001bindEvent$lambda6$lambda3(UserInfoSexActivity.this, (UserInfoBean) obj);
            }
        });
        getRadio_sex_female().setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: b.a.a.a.t.n.h
            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                UserInfoSexActivity.m6002bindEvent$lambda6$lambda4(UserInfoSexActivity.this, compoundButton, z);
            }
        });
        getRadio_sex_male().setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: b.a.a.a.t.n.e
            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                UserInfoSexActivity.m6003bindEvent$lambda6$lambda5(UserInfoSexActivity.this, compoundButton, z);
            }
        });
        C2354n.m2374A(getBtn_submit(), 0L, new Function1<AppCompatButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.UserInfoSexActivity$bindEvent$1$5
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(AppCompatButton appCompatButton) {
                invoke2(appCompatButton);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull AppCompatButton it) {
                int currentSexy;
                MineViewModel viewModel2;
                int currentSexy2;
                Intrinsics.checkNotNullParameter(it, "it");
                currentSexy = UserInfoSexActivity.this.getCurrentSexy();
                if (currentSexy == 0) {
                    C2354n.m2449Z("请选择性别");
                    return;
                }
                viewModel2 = UserInfoSexActivity.this.getViewModel();
                currentSexy2 = UserInfoSexActivity.this.getCurrentSexy();
                viewModel2.updateUserInfo("sex", String.valueOf(currentSexy2));
            }
        }, 1);
    }

    @NotNull
    public final AppCompatButton getBtn_submit() {
        return (AppCompatButton) this.btn_submit.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.activity_userinfo_sex;
    }

    @NotNull
    public final CheckBox getRadio_sex_female() {
        return (CheckBox) this.radio_sex_female.getValue();
    }

    @NotNull
    public final CheckBox getRadio_sex_male() {
        return (CheckBox) this.radio_sex_male.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "性别设置";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        MyApp myApp = MyApp.f9891f;
        initView(MyApp.f9892g);
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        MineViewModel.requestUserInfo$default(getViewModel(), false, false, 3, null);
    }

    @NotNull
    public final MineViewModel viewModelInstance() {
        return getViewModel();
    }
}
