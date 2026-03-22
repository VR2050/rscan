package com.jbzd.media.movecartoons.p396ui.settings;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Environment;
import android.os.Looper;
import android.widget.TextView;
import androidx.appcompat.widget.LinearLayoutCompat;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.databinding.ActivitySettingBinding;
import com.jbzd.media.movecartoons.p396ui.accountvoucher.FindActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import java.io.File;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0856l;
import p005b.p006a.p007a.p008a.p009a.C0874v;
import p005b.p006a.p007a.p008a.p009a.RunnableC0873u;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u0000 \u001f2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u001fB\u0007¢\u0006\u0004\b\u001e\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u0019\u0010\u000b\u001a\u00020\u00062\b\u0010\n\u001a\u0004\u0018\u00010\tH\u0014¢\u0006\u0004\b\u000b\u0010\fR\u001d\u0010\u0012\u001a\u00020\r8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0017\u001a\u00020\u00138F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u000f\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001a\u001a\u00020\u00138F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u000f\u001a\u0004\b\u0019\u0010\u0016R\u001d\u0010\u001d\u001a\u00020\r8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u000f\u001a\u0004\b\u001c\u0010\u0011¨\u0006 "}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/SettingActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActivitySettingBinding;", "", "getTopBarTitle", "()Ljava/lang/String;", "", "initView", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Landroid/widget/TextView;", "tv_size_cache$delegate", "Lkotlin/Lazy;", "getTv_size_cache", "()Landroid/widget/TextView;", "tv_size_cache", "Landroidx/appcompat/widget/LinearLayoutCompat;", "layout_user_nick$delegate", "getLayout_user_nick", "()Landroidx/appcompat/widget/LinearLayoutCompat;", "layout_user_nick", "layout_user_sex$delegate", "getLayout_user_sex", "layout_user_sex", "tv_version_name$delegate", "getTv_version_name", "tv_version_name", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SettingActivity extends BaseBindingActivity<ActivitySettingBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: tv_version_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_version_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$tv_version_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) SettingActivity.this.findViewById(R.id.tv_version_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: layout_user_nick$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_user_nick = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayoutCompat>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$layout_user_nick$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayoutCompat invoke() {
            LinearLayoutCompat linearLayoutCompat = (LinearLayoutCompat) SettingActivity.this.findViewById(R.id.layout_user_nick);
            Intrinsics.checkNotNull(linearLayoutCompat);
            return linearLayoutCompat;
        }
    });

    /* renamed from: layout_user_sex$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_user_sex = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayoutCompat>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$layout_user_sex$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayoutCompat invoke() {
            LinearLayoutCompat linearLayoutCompat = (LinearLayoutCompat) SettingActivity.this.findViewById(R.id.layout_user_sex);
            Intrinsics.checkNotNull(linearLayoutCompat);
            return linearLayoutCompat;
        }
    });

    /* renamed from: tv_size_cache$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_size_cache = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$tv_size_cache$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) SettingActivity.this.findViewById(R.id.tv_size_cache);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/settings/SettingActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, SettingActivity.class);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final LinearLayoutCompat getLayout_user_nick() {
        return (LinearLayoutCompat) this.layout_user_nick.getValue();
    }

    @NotNull
    public final LinearLayoutCompat getLayout_user_sex() {
        return (LinearLayoutCompat) this.layout_user_sex.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.setting);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.setting)");
        return string;
    }

    @NotNull
    public final TextView getTv_size_cache() {
        return (TextView) this.tv_size_cache.getValue();
    }

    @NotNull
    public final TextView getTv_version_name() {
        return (TextView) this.tv_version_name.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        bodyBinding(new Function1<ActivitySettingBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActivitySettingBinding activitySettingBinding) {
                invoke2(activitySettingBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActivitySettingBinding bodyBinding) {
                String str;
                String str2 = "";
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                TextView tv_version_name = SettingActivity.this.getTv_version_name();
                PackageManager packageManager = C4195m.m4792Y().getPackageManager();
                Intrinsics.checkNotNullExpressionValue(packageManager, "getApp().packageManager");
                try {
                    PackageInfo packageInfo = packageManager.getPackageInfo(C4195m.m4792Y().getPackageName(), 0);
                    Intrinsics.checkNotNullExpressionValue(packageInfo, "pm.getPackageInfo(Utils.getApp().packageName, 0)");
                    str = packageInfo.versionName;
                    Intrinsics.checkNotNullExpressionValue(str, "packageInfo.versionName");
                } catch (PackageManager.NameNotFoundException e2) {
                    e2.printStackTrace();
                    str = "";
                }
                tv_version_name.setText(Intrinsics.stringPlus("V ", str));
                LinearLayoutCompat layout_user_nick = SettingActivity.this.getLayout_user_nick();
                final SettingActivity settingActivity = SettingActivity.this;
                C2354n.m2374A(layout_user_nick, 0L, new Function1<LinearLayoutCompat, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$initView$1.1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayoutCompat linearLayoutCompat) {
                        invoke2(linearLayoutCompat);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayoutCompat it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        MineInfoActivity.Companion.start(SettingActivity.this);
                    }
                }, 1);
                LinearLayoutCompat layout_user_sex = SettingActivity.this.getLayout_user_sex();
                final SettingActivity settingActivity2 = SettingActivity.this;
                C2354n.m2374A(layout_user_sex, 0L, new Function1<LinearLayoutCompat, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$initView$1.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayoutCompat linearLayoutCompat) {
                        invoke2(linearLayoutCompat);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayoutCompat it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        UserInfoSexActivity.Companion.start(SettingActivity.this);
                    }
                }, 1);
                LinearLayoutCompat linearLayoutCompat = bodyBinding.layoutAvatarInfo;
                final SettingActivity settingActivity3 = SettingActivity.this;
                C2354n.m2374A(linearLayoutCompat, 0L, new Function1<LinearLayoutCompat, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$initView$1.3
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayoutCompat linearLayoutCompat2) {
                        invoke2(linearLayoutCompat2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayoutCompat it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        AvatarActivity.INSTANCE.start(SettingActivity.this);
                    }
                }, 1);
                LinearLayoutCompat linearLayoutCompat2 = bodyBinding.layoutFindAccount;
                final SettingActivity settingActivity4 = SettingActivity.this;
                C2354n.m2374A(linearLayoutCompat2, 0L, new Function1<LinearLayoutCompat, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$initView$1.4
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayoutCompat linearLayoutCompat3) {
                        invoke2(linearLayoutCompat3);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayoutCompat it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        FindActivity.INSTANCE.start(SettingActivity.this);
                    }
                }, 1);
                LinearLayoutCompat linearLayoutCompat3 = bodyBinding.layoutClearCache;
                final SettingActivity settingActivity5 = SettingActivity.this;
                C2354n.m2374A(linearLayoutCompat3, 0L, new Function1<LinearLayoutCompat, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$initView$1.5
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayoutCompat linearLayoutCompat4) {
                        invoke2(linearLayoutCompat4);
                        return Unit.INSTANCE;
                    }

                    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:27:0x00a8 -> B:14:0x00ab). Please report as a decompilation issue!!! */
                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayoutCompat it) {
                        File externalCacheDir;
                        Intrinsics.checkNotNullParameter(it, "it");
                        SettingActivity context = SettingActivity.this;
                        String[] filepath = new String[0];
                        Intrinsics.checkNotNullParameter(context, "context");
                        Intrinsics.checkNotNullParameter(filepath, "filepath");
                        Intrinsics.checkNotNullParameter(context, "context");
                        File cacheDir = context.getCacheDir();
                        Intrinsics.checkNotNullExpressionValue(cacheDir, "context.cacheDir");
                        C0856l.m192a(cacheDir);
                        Intrinsics.checkNotNullParameter(context, "context");
                        if (Intrinsics.areEqual(Environment.getExternalStorageState(), "mounted") && (externalCacheDir = context.getExternalCacheDir()) != null) {
                            C0856l.m192a(externalCacheDir);
                        }
                        Intrinsics.checkNotNullParameter(context, "context");
                        C0856l.m192a(new File(context.getCacheDir().getParent(), "databases"));
                        Intrinsics.checkNotNullParameter(context, "context");
                        C0856l.m192a(new File(context.getCacheDir().getParent(), "shared_prefs"));
                        Intrinsics.checkNotNullParameter(context, "context");
                        File filesDir = context.getFilesDir();
                        Intrinsics.checkNotNullExpressionValue(filesDir, "context.filesDir");
                        C0856l.m192a(filesDir);
                        if (C0874v.f311a == null) {
                            C0874v.f311a = new C0874v();
                        }
                        C0874v c0874v = C0874v.f311a;
                        SettingActivity settingActivity6 = SettingActivity.this;
                        Objects.requireNonNull(c0874v);
                        try {
                            if (Looper.myLooper() == Looper.getMainLooper()) {
                                new Thread(new RunnableC0873u(c0874v, settingActivity6)).start();
                            } else {
                                ComponentCallbacks2C1553c.m735d(settingActivity6).m740b();
                            }
                        } catch (Exception e3) {
                            e3.printStackTrace();
                        }
                        try {
                            if (Looper.myLooper() == Looper.getMainLooper()) {
                                ComponentCallbacks2C1553c.m735d(settingActivity6).m741c();
                            }
                        } catch (Exception e4) {
                            e4.printStackTrace();
                        }
                        c0874v.m202a(settingActivity6.getExternalCacheDir() + "image_manager_disk_cache", true);
                        SettingActivity.this.getTv_size_cache().setText("0Byte");
                        C2354n.m2409L1("清理完成");
                    }
                }, 1);
                TextView tv_size_cache = SettingActivity.this.getTv_size_cache();
                if (C0874v.f311a == null) {
                    C0874v.f311a = new C0874v();
                }
                C0874v c0874v = C0874v.f311a;
                SettingActivity settingActivity6 = SettingActivity.this;
                Objects.requireNonNull(c0874v);
                try {
                    str2 = C0874v.m201c(c0874v.m203b(new File(settingActivity6.getCacheDir() + "/image_manager_disk_cache")));
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
                tv_size_cache.setText(str2);
                LinearLayoutCompat linearLayoutCompat4 = bodyBinding.layoutAccountCreate;
                final SettingActivity settingActivity7 = SettingActivity.this;
                C2354n.m2374A(linearLayoutCompat4, 0L, new Function1<LinearLayoutCompat, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.SettingActivity$initView$1.6
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(LinearLayoutCompat linearLayoutCompat5) {
                        invoke2(linearLayoutCompat5);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull LinearLayoutCompat it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        LoginActivity.INSTANCE.start(SettingActivity.this);
                    }
                }, 1);
                SettingActivity settingActivity8 = SettingActivity.this;
                BaseBindingActivity.fadeWhenTouch$default(settingActivity8, settingActivity8.getLayout_user_nick(), 0.0f, 1, null);
                SettingActivity settingActivity9 = SettingActivity.this;
                BaseBindingActivity.fadeWhenTouch$default(settingActivity9, settingActivity9.getLayout_user_sex(), 0.0f, 1, null);
                SettingActivity settingActivity10 = SettingActivity.this;
                LinearLayoutCompat layoutAvatarInfo = bodyBinding.layoutAvatarInfo;
                Intrinsics.checkNotNullExpressionValue(layoutAvatarInfo, "layoutAvatarInfo");
                BaseBindingActivity.fadeWhenTouch$default(settingActivity10, layoutAvatarInfo, 0.0f, 1, null);
                SettingActivity settingActivity11 = SettingActivity.this;
                LinearLayoutCompat layoutFindAccount = bodyBinding.layoutFindAccount;
                Intrinsics.checkNotNullExpressionValue(layoutFindAccount, "layoutFindAccount");
                BaseBindingActivity.fadeWhenTouch$default(settingActivity11, layoutFindAccount, 0.0f, 1, null);
                SettingActivity settingActivity12 = SettingActivity.this;
                LinearLayoutCompat layoutClearCache = bodyBinding.layoutClearCache;
                Intrinsics.checkNotNullExpressionValue(layoutClearCache, "layoutClearCache");
                BaseBindingActivity.fadeWhenTouch$default(settingActivity12, layoutClearCache, 0.0f, 1, null);
                SettingActivity settingActivity13 = SettingActivity.this;
                LinearLayoutCompat layoutAccountCreate = bodyBinding.layoutAccountCreate;
                Intrinsics.checkNotNullExpressionValue(layoutAccountCreate, "layoutAccountCreate");
                BaseBindingActivity.fadeWhenTouch$default(settingActivity13, layoutAccountCreate, 0.0f, 1, null);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
    }
}
