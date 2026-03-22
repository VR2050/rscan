package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.Context;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.view.ProgressButton;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Lazy;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u000b\u0018\u0000 \u00132\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0013B\u0007¢\u0006\u0004\b\u0012\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\f\u0010\rR\u001d\u0010\u0011\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\r¨\u0006\u0014"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/ModifyNicknameActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "", "bindEvent", "()V", "", "getLayoutId", "()I", "", "getTopBarTitle", "()Ljava/lang/String;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ModifyNicknameActivity extends MyThemeViewModelActivity<MineViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(MineViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.settings.ModifyNicknameActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.settings.ModifyNicknameActivity$special$$inlined$viewModels$default$1
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

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/ModifyNicknameActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, ModifyNicknameActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MineViewModel getViewModel() {
        return (MineViewModel) this.viewModel.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        String str;
        TextView textView = (TextView) findViewById(R$id.tvTitle);
        MyApp myApp = MyApp.f9891f;
        UserInfoBean userInfoBean = MyApp.f9892g;
        String str2 = "";
        if (userInfoBean != null && (str = userInfoBean.nickname) != null) {
            str2 = str;
        }
        textView.setText(Intrinsics.stringPlus("当前昵称：", str2));
        MineViewModel viewModel = getViewModel();
        viewModel.getLoading().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.settings.ModifyNicknameActivity$bindEvent$lambda-2$$inlined$observe$1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                ((ProgressButton) ModifyNicknameActivity.this.findViewById(R$id.submit)).setProgress(((C2848a) t).f7763a);
            }
        });
        viewModel.getUserInfoUpdateSuccess().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.settings.ModifyNicknameActivity$bindEvent$lambda-2$$inlined$observe$2
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                Boolean it = (Boolean) t;
                Intrinsics.checkNotNullExpressionValue(it, "it");
                if (it.booleanValue()) {
                    C2354n.m2409L1("修改成功");
                    ModifyNicknameActivity.this.finish();
                }
            }
        });
        ((AppCompatEditText) findViewById(R$id.et_content)).addTextChangedListener(new TextWatcher() { // from class: com.jbzd.media.movecartoons.ui.settings.ModifyNicknameActivity$bindEvent$2
            @Override // android.text.TextWatcher
            public void afterTextChanged(@Nullable Editable s) {
                ((ProgressButton) ModifyNicknameActivity.this.findViewById(R$id.submit)).setEnable(StringsKt__StringsKt.trim((CharSequence) String.valueOf(s)).toString().length() > 0);
            }

            @Override // android.text.TextWatcher
            public void beforeTextChanged(@Nullable CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(@Nullable CharSequence s, int start, int before, int count) {
            }
        });
        C2354n.m2374A((ProgressButton) findViewById(R$id.submit), 0L, new Function1<ProgressButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.ModifyNicknameActivity$bindEvent$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ProgressButton progressButton) {
                invoke2(progressButton);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ProgressButton progressButton) {
                MineViewModel viewModel2;
                String obj = StringsKt__StringsKt.trim((CharSequence) String.valueOf(((AppCompatEditText) ModifyNicknameActivity.this.findViewById(R$id.et_content)).getText())).toString();
                if (!(!TextUtils.isEmpty(obj))) {
                    C2354n.m2449Z("请输入昵称");
                } else {
                    viewModel2 = ModifyNicknameActivity.this.getViewModel();
                    viewModel2.updateUserInfo("nickname", obj);
                }
            }
        }, 1);
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_modify_nickname;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "昵称";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public MineViewModel viewModelInstance() {
        return getViewModel();
    }
}
