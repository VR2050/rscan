package com.jbzd.media.movecartoons.p396ui.index.home.child;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
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
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0016\u0018\u0000 +2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001+B\u0007¢\u0006\u0004\b*\u0010\tJ\u0019\u0010\u0006\u001a\u00020\u00052\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003H\u0014¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\r\u0010\u0010\u001a\u00020\u0002¢\u0006\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0015\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0011R\u001d\u0010\u001a\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0013\u001a\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001d\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0013\u001a\u0004\b\u001c\u0010\u0019R\u001d\u0010 \u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u0013\u001a\u0004\b\u001f\u0010\u0019R\u001d\u0010#\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u0013\u001a\u0004\b\"\u0010\u0019R\u001d\u0010&\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u0013\u001a\u0004\b%\u0010\u0019R\u001d\u0010)\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u0013\u001a\u0004\b(\u0010\u0019¨\u0006,"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/child/CreaterApplyActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "Landroid/os/Bundle;", "savedInstanceState", "", "onCreate", "(Landroid/os/Bundle;)V", "bindEvent", "()V", "", "getLayoutId", "()I", "", "getTopBarTitle", "()Ljava/lang/String;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "Landroid/widget/TextView;", "btn_apply$delegate", "getBtn_apply", "()Landroid/widget/TextView;", "btn_apply", "tv_service_link$delegate", "getTv_service_link", "tv_service_link", "tv_grouplink_join$delegate", "getTv_grouplink_join", "tv_grouplink_join", "tv_serviceemail_copy$delegate", "getTv_serviceemail_copy", "tv_serviceemail_copy", "tv_servicelink_copy$delegate", "getTv_servicelink_copy", "tv_servicelink_copy", "tv_official_gmail$delegate", "getTv_official_gmail", "tv_official_gmail", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CreaterApplyActivity extends MyThemeActivity<MineViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: btn_apply$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_apply = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$btn_apply$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) CreaterApplyActivity.this.findViewById(R.id.btn_apply);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_service_link$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_service_link = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$tv_service_link$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) CreaterApplyActivity.this.findViewById(R.id.tv_service_link);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_official_gmail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_official_gmail = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$tv_official_gmail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) CreaterApplyActivity.this.findViewById(R.id.tv_official_gmail);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_servicelink_copy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_servicelink_copy = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$tv_servicelink_copy$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) CreaterApplyActivity.this.findViewById(R.id.tv_servicelink_copy);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_grouplink_join$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_grouplink_join = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$tv_grouplink_join$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) CreaterApplyActivity.this.findViewById(R.id.tv_grouplink_join);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_serviceemail_copy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_serviceemail_copy = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$tv_serviceemail_copy$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) CreaterApplyActivity.this.findViewById(R.id.tv_serviceemail_copy);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(MineViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$special$$inlined$viewModels$default$1
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

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/child/CreaterApplyActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) CreaterApplyActivity.class);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    private final MineViewModel getViewModel() {
        return (MineViewModel) this.viewModel.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getViewModel();
        TextView tv_service_link = getTv_service_link();
        MyApp myApp = MyApp.f9891f;
        tv_service_link.setText(MyApp.m4185f().service_link);
        getTv_official_gmail().setText(MyApp.m4185f().service_email);
        C2354n.m2374A(getTv_servicelink_copy(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$bindEvent$1$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                Object systemService = CreaterApplyActivity.this.getApplication().getSystemService("clipboard");
                Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.content.ClipboardManager");
                MyApp myApp2 = MyApp.f9891f;
                ((ClipboardManager) systemService).setPrimaryClip(ClipData.newPlainText(MyApp.m4185f().service_link, MyApp.m4185f().service_link));
                C2354n.m2409L1("复制成功");
            }
        }, 1);
        C2354n.m2374A(getTv_grouplink_join(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$bindEvent$1$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C0840d.a aVar = C0840d.f235a;
                CreaterApplyActivity createrApplyActivity = CreaterApplyActivity.this;
                MyApp myApp2 = MyApp.f9891f;
                String str = MyApp.m4185f().service_link;
                if (str == null) {
                    str = "";
                }
                C0840d.a.m174d(aVar, createrApplyActivity, str, null, null, 12);
            }
        }, 1);
        C2354n.m2374A(getTv_serviceemail_copy(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$bindEvent$1$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                Object systemService = CreaterApplyActivity.this.getApplication().getSystemService("clipboard");
                Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.content.ClipboardManager");
                MyApp myApp2 = MyApp.f9891f;
                ((ClipboardManager) systemService).setPrimaryClip(ClipData.newPlainText(MyApp.m4185f().service_email, MyApp.m4185f().service_email));
                C2354n.m2409L1("复制成功");
            }
        }, 1);
        C2354n.m2374A(getBtn_apply(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.CreaterApplyActivity$bindEvent$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C2354n.m2525w0("点击了申请提交...");
            }
        }, 1);
    }

    @NotNull
    public final TextView getBtn_apply() {
        return (TextView) this.btn_apply.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_creater_apply;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "认证申请";
    }

    @NotNull
    public final TextView getTv_grouplink_join() {
        return (TextView) this.tv_grouplink_join.getValue();
    }

    @NotNull
    public final TextView getTv_official_gmail() {
        return (TextView) this.tv_official_gmail.getValue();
    }

    @NotNull
    public final TextView getTv_service_link() {
        return (TextView) this.tv_service_link.getValue();
    }

    @NotNull
    public final TextView getTv_serviceemail_copy() {
        return (TextView) this.tv_serviceemail_copy.getValue();
    }

    @NotNull
    public final TextView getTv_servicelink_copy() {
        return (TextView) this.tv_servicelink_copy.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle("认证申请");
        getBtn_apply().setText("申请提交");
    }

    @NotNull
    public final MineViewModel viewModelInstance() {
        return getViewModel();
    }
}
