package com.jbzd.media.movecartoons.p396ui.splash;

import android.animation.ObjectAnimator;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.constraintlayout.motion.widget.Key;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.DialogController;
import com.jbzd.media.movecartoons.p396ui.dialog.RobotDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.UpdateDialog;
import com.jbzd.media.movecartoons.p396ui.index.IndexActivity;
import com.jbzd.media.movecartoons.p396ui.splash.SplashActivity;
import com.jbzd.media.movecartoons.p396ui.splash.SplashActivity$mAdapter$2;
import com.jbzd.media.movecartoons.p396ui.splash.SplashViewMode;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp3;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;
import com.youth.banner.adapter.BannerAdapter;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import com.youth.banner.listener.OnPageChangeListener;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.locks.LockSupport;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.coroutines.ContinuationInterceptor;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.C0885h;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0846g;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p337d.C2858b;
import p005b.p327w.p330b.p337d.C2859c;
import p379c.p380a.AbstractC3036c0;
import p379c.p380a.AbstractC3091q0;
import p379c.p380a.C3054e;
import p379c.p380a.C3071j1;
import p379c.p380a.C3079m0;
import p379c.p380a.C3107v1;
import p379c.p380a.C3108w;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3115y0;
import p379c.p380a.p381a.C2964m;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000k\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\b\u0005\n\u0002\u0010!\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\u0007*\u0001@\u0018\u0000 [2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001[B\u0007¢\u0006\u0004\bZ\u0010\u0012J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J%\u0010\f\u001a\u00020\u00052\f\u0010\n\u001a\b\u0012\u0004\u0012\u00020\t0\b2\u0006\u0010\u000b\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\f\u0010\rJ\u001d\u0010\u000f\u001a\u00020\u00052\f\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\t0\bH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\u001f\u0010\u0017\u001a\u00020\u00052\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0016\u001a\u00020\u0015H\u0002¢\u0006\u0004\b\u0017\u0010\u0018J\u001f\u0010\u001b\u001a\u00020\u00052\u0006\u0010\u000b\u001a\u00020\u00032\u0006\u0010\u001a\u001a\u00020\u0019H\u0002¢\u0006\u0004\b\u001b\u0010\u001cJ\u0017\u0010\u001d\u001a\u00020\u00052\u0006\u0010\u000b\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u001d\u0010\u0007J\u0017\u0010\u001f\u001a\u00020\u00052\u0006\u0010\u001e\u001a\u00020\u0015H\u0002¢\u0006\u0004\b\u001f\u0010 J\u0017\u0010!\u001a\u00020\u00052\u0006\u0010\u001e\u001a\u00020\u0015H\u0002¢\u0006\u0004\b!\u0010 J\u0017\u0010#\u001a\u00020\u00052\u0006\u0010\"\u001a\u00020\u0015H\u0002¢\u0006\u0004\b#\u0010 J\u000f\u0010$\u001a\u00020\u0002H\u0016¢\u0006\u0004\b$\u0010%J\u000f\u0010&\u001a\u00020\u0005H\u0016¢\u0006\u0004\b&\u0010\u0012J\u0019\u0010)\u001a\u00020\u00052\b\u0010(\u001a\u0004\u0018\u00010'H\u0014¢\u0006\u0004\b)\u0010*J\u001b\u0010,\u001a\u00020+2\f\u0010\n\u001a\b\u0012\u0004\u0012\u00020\t0\b¢\u0006\u0004\b,\u0010-J)\u00102\u001a\u00020\u00052\u0006\u0010.\u001a\u00020\u00132\u0006\u0010/\u001a\u00020\u00132\b\u00101\u001a\u0004\u0018\u000100H\u0014¢\u0006\u0004\b2\u00103J\u000f\u00104\u001a\u00020\u0013H\u0016¢\u0006\u0004\b4\u00105J\r\u00106\u001a\u00020\u0005¢\u0006\u0004\b6\u0010\u0012J\u000f\u00107\u001a\u00020\u0005H\u0016¢\u0006\u0004\b7\u0010\u0012R\"\u0010\u0004\u001a\u00020\u00038\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0004\u00108\u001a\u0004\b9\u0010:\"\u0004\b;\u0010\u0007R\u001d\u0010?\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b<\u0010=\u001a\u0004\b>\u0010%R\u001d\u0010D\u001a\u00020@8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bA\u0010=\u001a\u0004\bB\u0010CR.\u0010F\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\t0\b0E8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bF\u0010G\u001a\u0004\bH\u0010I\"\u0004\bJ\u0010\u0010R\u0018\u0010K\u001a\u0004\u0018\u00010+8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bK\u0010LR\"\u0010M\u001a\u00020\u00138\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bM\u0010N\u001a\u0004\bO\u00105\"\u0004\bP\u0010QR\"\u0010R\u001a\u00020\u00138\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bR\u0010N\u001a\u0004\bS\u00105\"\u0004\bT\u0010QR%\u0010Y\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030U8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bV\u0010=\u001a\u0004\bW\u0010X¨\u0006\\"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/splash/SplashActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/splash/SplashViewMode;", "Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;", "mSystemInfoBean", "", "checkPingUrl", "(Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;)V", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "adBean", "systemInfoBean", "showAdView", "(Ljava/util/List;Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;)V", "mBanners", "initBannerView", "(Ljava/util/List;)V", "goMainPage", "()V", "", "time", "", "jump", "countDown", "(ILjava/lang/String;)V", "", "isMandatoryUpdate", "showUpdateDialog", "(Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;Z)V", "downloadNewVersion", "filePath", "requestInstall", "(Ljava/lang/String;)V", "grantedInstallApk", NotificationCompat.CATEGORY_MESSAGE, "doCantUse", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/splash/SplashViewMode;", "bindEvent", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Lc/a/d1;", "main", "(Ljava/util/List;)Lc/a/d1;", "requestCode", "resultCode", "Landroid/content/Intent;", "data", "onActivityResult", "(IILandroid/content/Intent;)V", "getLayoutId", "()I", "goMain", "releaseResources", "Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;", "getMSystemInfoBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;", "setMSystemInfoBean", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "com/jbzd/media/movecartoons/ui/splash/SplashActivity$mAdapter$2$1", "mAdapter$delegate", "getMAdapter", "()Lcom/jbzd/media/movecartoons/ui/splash/SplashActivity$mAdapter$2$1;", "mAdapter", "", "mBanners2", "Ljava/util/List;", "getMBanners2", "()Ljava/util/List;", "setMBanners2", "jobCountDown", "Lc/a/d1;", "cdnLengh", "I", "getCdnLengh", "setCdnLengh", "(I)V", "checkCdnPosition", "getCheckCdnPosition", "setCheckCdnPosition", "Lcom/youth/banner/Banner;", "banner_splash$delegate", "getBanner_splash", "()Lcom/youth/banner/Banner;", "banner_splash", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SplashActivity extends MyThemeViewModelActivity<SplashViewMode> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private int cdnLengh;
    private int checkCdnPosition;

    @Nullable
    private InterfaceC3053d1 jobCountDown;
    public SystemInfoBean mSystemInfoBean;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(SplashViewMode.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$special$$inlined$viewModels$default$1
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

    /* renamed from: mAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mAdapter = LazyKt__LazyJVMKt.lazy(new Function0<SplashActivity$mAdapter$2.C38921>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$mAdapter$2

        @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001d\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\b¨\u0006\t"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/splash/SplashActivity$mAdapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
        /* renamed from: com.jbzd.media.movecartoons.ui.splash.SplashActivity$mAdapter$2$1 */
        public static final class C38921 extends BaseQuickAdapter<String, BaseViewHolder> {
            public final /* synthetic */ SplashActivity this$0;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public C38921(final SplashActivity splashActivity) {
                super(R.layout.item_site, null, 2, null);
                this.this$0 = splashActivity;
                setOnItemClickListener(
                /*  JADX ERROR: Method code generation error
                    jadx.core.utils.exceptions.CodegenException: Error generate insn: 0x000f: INVOKE 
                      (r3v0 'this' com.jbzd.media.movecartoons.ui.splash.SplashActivity$mAdapter$2$1 A[IMMUTABLE_TYPE, THIS])
                      (wrap:b.b.a.a.a.k.d:0x000c: CONSTRUCTOR 
                      (r3v0 'this' com.jbzd.media.movecartoons.ui.splash.SplashActivity$mAdapter$2$1 A[DONT_INLINE, IMMUTABLE_TYPE, THIS])
                      (r4v0 'splashActivity' com.jbzd.media.movecartoons.ui.splash.SplashActivity A[DONT_INLINE])
                     A[MD:(com.jbzd.media.movecartoons.ui.splash.SplashActivity$mAdapter$2$1, com.jbzd.media.movecartoons.ui.splash.SplashActivity):void (m), WRAPPED] (LINE:2) call: b.a.a.a.t.p.g.<init>(com.jbzd.media.movecartoons.ui.splash.SplashActivity$mAdapter$2$1, com.jbzd.media.movecartoons.ui.splash.SplashActivity):void type: CONSTRUCTOR)
                     VIRTUAL call: com.chad.library.adapter.base.BaseQuickAdapter.setOnItemClickListener(b.b.a.a.a.k.d):void A[MD:(b.b.a.a.a.k.d):void (m)] (LINE:2) in method: com.jbzd.media.movecartoons.ui.splash.SplashActivity$mAdapter$2.1.<init>(com.jbzd.media.movecartoons.ui.splash.SplashActivity):void, file: classes2.dex
                    	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:310)
                    	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:273)
                    	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:94)
                    	at jadx.core.dex.nodes.IBlock.generate(IBlock.java:15)
                    	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:66)
                    	at jadx.core.dex.regions.Region.generate(Region.java:35)
                    	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:66)
                    	at jadx.core.dex.regions.Region.generate(Region.java:35)
                    	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:66)
                    	at jadx.core.codegen.MethodGen.addRegionInsns(MethodGen.java:297)
                    	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:276)
                    	at jadx.core.codegen.ClassGen.addMethodCode(ClassGen.java:406)
                    	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:335)
                    	at jadx.core.codegen.ClassGen.lambda$addInnerClsAndMethods$3(ClassGen.java:301)
                    	at java.base/java.util.stream.ForEachOps$ForEachOp$OfRef.accept(ForEachOps.java:184)
                    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1596)
                    	at java.base/java.util.stream.SortedOps$RefSortingSink.end(SortedOps.java:395)
                    	at java.base/java.util.stream.Sink$ChainedReference.end(Sink.java:261)
                    Caused by: jadx.core.utils.exceptions.JadxRuntimeException: Expected class to be processed at this point, class: b.a.a.a.t.p.g, state: NOT_LOADED
                    	at jadx.core.dex.nodes.ClassNode.ensureProcessed(ClassNode.java:305)
                    	at jadx.core.codegen.InsnGen.inlineAnonymousConstructor(InsnGen.java:807)
                    	at jadx.core.codegen.InsnGen.makeConstructor(InsnGen.java:730)
                    	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:418)
                    	at jadx.core.codegen.InsnGen.addWrappedArg(InsnGen.java:145)
                    	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:121)
                    	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:108)
                    	at jadx.core.codegen.InsnGen.generateMethodArguments(InsnGen.java:1143)
                    	at jadx.core.codegen.InsnGen.makeInvoke(InsnGen.java:910)
                    	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:422)
                    	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:303)
                    	... 17 more
                    */
                /*
                    this = this;
                    r3.this$0 = r4
                    r0 = 2131558777(0x7f0d0179, float:1.874288E38)
                    r1 = 0
                    r2 = 2
                    r3.<init>(r0, r1, r2, r1)
                    b.a.a.a.t.p.g r0 = new b.a.a.a.t.p.g
                    r0.<init>(r3, r4)
                    r3.setOnItemClickListener(r0)
                    return
                */
                throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.splash.SplashActivity$mAdapter$2.C38921.<init>(com.jbzd.media.movecartoons.ui.splash.SplashActivity):void");
            }

            /* JADX INFO: Access modifiers changed from: private */
            /* renamed from: _init_$lambda-1, reason: not valid java name */
            public static final void m6013_init_$lambda1(C38921 this$0, SplashActivity this$1, BaseQuickAdapter adapter, View view, int i2) {
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(this$1, "this$1");
                Intrinsics.checkNotNullParameter(adapter, "adapter");
                Intrinsics.checkNotNullParameter(view, "view");
                C0840d.f235a.m175a(this$1, this$0.getItem(i2));
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull String item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                helper.m3919i(R.id.f13004tv, item);
            }
        }

        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C38921 invoke() {
            return new C38921(SplashActivity.this);
        }
    });

    /* renamed from: banner_splash$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner_splash = LazyKt__LazyJVMKt.lazy(new Function0<Banner<?, ?>>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$banner_splash$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final Banner<?, ?> invoke() {
            Banner<?, ?> banner = (Banner) SplashActivity.this.findViewById(R.id.banner_splash);
            Intrinsics.checkNotNull(banner);
            return banner;
        }
    });

    @NotNull
    private List<List<AdBean>> mBanners2 = new ArrayList();

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/splash/SplashActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, SplashActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-1, reason: not valid java name */
    public static final void m6006bindEvent$lambda6$lambda1(SplashActivity this$0, Boolean showError) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        FrameLayout frameLayout = (FrameLayout) this$0.findViewById(R$id.off_line_layout);
        Intrinsics.checkNotNullExpressionValue(showError, "showError");
        frameLayout.setVisibility(showError.booleanValue() ? 0 : 8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-2, reason: not valid java name */
    public static final void m6007bindEvent$lambda6$lambda2(SplashActivity this$0, Boolean bool) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ((TextView) this$0.findViewById(R$id.tv_line_state)).setText("检测成功");
        ObjectAnimator ofFloat = ObjectAnimator.ofFloat((LinearLayout) this$0.findViewById(R$id.ll_line_checking), Key.ALPHA, 2.0f, 0.0f);
        Intrinsics.checkNotNullExpressionValue(ofFloat, "ofFloat(ll_line_checking, \"alpha\", 2f, 0f)");
        ofFloat.setDuration(1000L);
        ofFloat.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-3, reason: not valid java name */
    public static final void m6008bindEvent$lambda6$lambda3(SplashActivity this$0, SplashViewMode this_run, SystemInfoBean systemInfoBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullExpressionValue(systemInfoBean, "systemInfoBean");
        this$0.setMSystemInfoBean(systemInfoBean);
        SystemInfoBean value = this_run.getSystemInfoBody().getValue();
        if (StringsKt__StringsJVMKt.equals$default(value == null ? null : value.is_verify, "n", false, 2, null)) {
            new RobotDialog(this$0, this$0.getViewModel(), "", new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$bindEvent$3$3$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(String str) {
                    invoke2(str);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull String it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            }).show(this$0.getSupportFragmentManager(), "ComicsChapterRobotDialog");
            return;
        }
        String channel = this$0.getViewModel().getChannel();
        if (channel == null || channel.length() == 0) {
            String clipboardValue = this$0.getViewModel().getClipboardValue();
            if (!(clipboardValue == null || clipboardValue.length() == 0)) {
                this$0.getViewModel().bindParent();
            }
        } else {
            this$0.getViewModel().bindChannel();
        }
        this$0.checkPingUrl(systemInfoBean);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-4, reason: not valid java name */
    public static final void m6009bindEvent$lambda6$lambda4(SplashActivity this$0, Boolean it) {
        String str;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (it.booleanValue()) {
            String str2 = this$0.getMSystemInfoBean().can_use;
            boolean z = true;
            if (!(!(str2 == null || str2.length() == 0) && Intrinsics.areEqual(str2, "y"))) {
                String str3 = this$0.getMSystemInfoBean().error_msg;
                Intrinsics.checkNotNullExpressionValue(str3, "mSystemInfoBean.error_msg");
                this$0.doCantUse(str3);
                return;
            }
            String str4 = this$0.getMSystemInfoBean().min_version;
            String str5 = "";
            if (!(str4 == null || str4.length() == 0)) {
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
                if (C2354n.m2389F(str, this$0.getMSystemInfoBean().min_version) == -1) {
                    this$0.showUpdateDialog(this$0.getMSystemInfoBean(), true);
                    return;
                }
            }
            String str6 = this$0.getMSystemInfoBean().version;
            if (str6 != null && str6.length() != 0) {
                z = false;
            }
            if (!z) {
                PackageManager packageManager2 = C4195m.m4792Y().getPackageManager();
                Intrinsics.checkNotNullExpressionValue(packageManager2, "getApp().packageManager");
                try {
                    PackageInfo packageInfo2 = packageManager2.getPackageInfo(C4195m.m4792Y().getPackageName(), 0);
                    Intrinsics.checkNotNullExpressionValue(packageInfo2, "pm.getPackageInfo(Utils.getApp().packageName, 0)");
                    String str7 = packageInfo2.versionName;
                    Intrinsics.checkNotNullExpressionValue(str7, "packageInfo.versionName");
                    str5 = str7;
                } catch (PackageManager.NameNotFoundException e3) {
                    e3.printStackTrace();
                }
                if (C2354n.m2389F(str5, this$0.getMSystemInfoBean().version) == -1) {
                    this$0.showUpdateDialog(this$0.getMSystemInfoBean(), false);
                    return;
                }
            }
            if (this$0.getMSystemInfoBean().f10031ad == null) {
                this$0.goMain();
                return;
            }
            List<AdBean> list = this$0.getMSystemInfoBean().f10031ad;
            Intrinsics.checkNotNullExpressionValue(list, "mSystemInfoBean.ad");
            this$0.showAdView(list, this$0.getMSystemInfoBean());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-5, reason: not valid java name */
    public static final void m6010bindEvent$lambda6$lambda5(SplashViewMode this_run, Boolean it) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (it.booleanValue()) {
            this_run.startPing();
        }
    }

    private final void checkPingUrl(SystemInfoBean mSystemInfoBean) {
        StringsKt__StringsJVMKt.replace$default(mSystemInfoBean.cdn_ping.get(this.checkCdnPosition).ping_url.toString(), "\\", "", false, 4, (Object) null);
        getViewModel().systemCdn("none");
    }

    private final void countDown(int time, String jump) {
        cancelJob(this.jobCountDown);
        ((TextView) findViewById(R$id.tv_adTime)).setText(time + " 秒");
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        this.jobCountDown = C2354n.m2435U0(c3109w0, C2964m.f8127b, 0, new SplashActivity$countDown$1(time, jump, this, null), 2, null);
    }

    private final void doCantUse(String msg) {
        DialogController dialogController = DialogController.INSTANCE;
        FragmentManager supportFragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
        DialogController.showHintDialog$default(dialogController, supportFragmentManager, null, msg, null, false, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$doCantUse$1
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                SplashActivity.this.finish();
            }
        }, 10, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void downloadNewVersion(SystemInfoBean systemInfoBean) {
        String str = systemInfoBean.download_url;
        ProgressDialog progressDialog = new ProgressDialog(this);
        progressDialog.setProgressStyle(1);
        progressDialog.setTitle("下载中...");
        progressDialog.setCancelable(false);
        progressDialog.setCanceledOnTouchOutside(false);
        progressDialog.setMax(100);
        progressDialog.show();
        if (C2859c.f7782a == null) {
            C2859c.f7782a = new C2859c();
        }
        C2859c c2859c = C2859c.f7782a;
        MyApp myApp = MyApp.f9891f;
        File externalFilesDir = MyApp.m4183d().getExternalFilesDir("apk");
        Intrinsics.checkNotNull(externalFilesDir);
        String absolutePath = externalFilesDir.getAbsolutePath();
        Intrinsics.checkNotNullExpressionValue(absolutePath, "MyApp.instance.getExternalFilesDir(\"apk\")!!.absolutePath");
        c2859c.m3302a(str, absolutePath, "new.apk", new SplashActivity$downloadNewVersion$1(progressDialog, this));
    }

    private final SplashActivity$mAdapter$2.C38921 getMAdapter() {
        return (SplashActivity$mAdapter$2.C38921) this.mAdapter.getValue();
    }

    private final SplashViewMode getViewModel() {
        return (SplashViewMode) this.viewModel.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void goMainPage() {
        cancelJob(this.jobCountDown);
        goMain();
    }

    private final void grantedInstallApk(String filePath) {
        C2858b.m3301b(this, new File(filePath));
    }

    private final void initBannerView(final List<? extends AdBean> mBanners) {
        BannerAdapter bannerAdapterImp;
        this.mBanners2 = TypeIntrinsics.asMutableList(CollectionsKt___CollectionsKt.chunked(mBanners, 3));
        if (mBanners == null || mBanners.isEmpty()) {
            ((LinearLayout) findViewById(R$id.banner_parent_splash)).setVisibility(8);
            return;
        }
        final Banner<?, ?> banner_splash = getBanner_splash();
        banner_splash.setIntercept(mBanners.size() != 1);
        Banner addBannerLifecycleObserver = banner_splash.addBannerLifecycleObserver(this);
        MyApp myApp = MyApp.f9891f;
        if (MyApp.m4185f().app_start_ad_show_method.equals("three")) {
            Context context = banner_splash.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "context");
            bannerAdapterImp = new BannerAdapterImp3(context, getMBanners2(), 0.0f, 88.0d, ImageView.ScaleType.FIT_XY, 4);
        } else {
            Context context2 = banner_splash.getContext();
            Intrinsics.checkNotNullExpressionValue(context2, "context");
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(mBanners, 10));
            Iterator<T> it = mBanners.iterator();
            while (it.hasNext()) {
                arrayList.add(((AdBean) it.next()).content);
            }
            bannerAdapterImp = new BannerAdapterImp(context2, arrayList, 0.0f, 88.0d, ImageView.ScaleType.FIT_XY, 4);
        }
        addBannerLifecycleObserver.setAdapter(bannerAdapterImp);
        banner_splash.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.p.e
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                SplashActivity.m6011initBannerView$lambda9$lambda8(Banner.this, mBanners, obj, i2);
            }
        });
        banner_splash.setIndicator(new RectangleIndicator(banner_splash.getContext()));
        banner_splash.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$initBannerView$1$3
            @Override // com.youth.banner.listener.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // com.youth.banner.listener.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // com.youth.banner.listener.OnPageChangeListener
            public void onPageSelected(int position) {
            }
        });
        banner_splash.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBannerView$lambda-9$lambda-8, reason: not valid java name */
    public static final void m6011initBannerView$lambda9$lambda8(Banner this_run, List mBanners, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(mBanners, "$mBanners");
        C0840d.a aVar = C0840d.f235a;
        Context context = this_run.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        aVar.m176b(context, (AdBean) mBanners.get(i2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void requestInstall(String filePath) {
        if (Build.VERSION.SDK_INT < 26) {
            grantedInstallApk(filePath);
        } else if (getPackageManager().canRequestPackageInstalls()) {
            grantedInstallApk(filePath);
        } else {
            C2354n.m2379B1(getString(R.string.toast_no_permission));
            startActivityForResult(new Intent("android.settings.MANAGE_UNKNOWN_APP_SOURCES", Uri.parse(Intrinsics.stringPlus("package:", getPackageName()))), 10010);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showAdView(List<? extends AdBean> adBean, SystemInfoBean systemInfoBean) {
        int i2 = R$id.tv_adTime;
        ((TextView) findViewById(i2)).setVisibility(0);
        ((TextView) findViewById(i2)).setText(Intrinsics.stringPlus(systemInfoBean.ad_show_time, " 秒"));
        C2354n.m2374A((TextView) findViewById(i2), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$showAdView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView) {
                if (TextUtils.equals(((TextView) SplashActivity.this.findViewById(R$id.tv_adTime)).getText().toString(), "进入")) {
                    SplashActivity.this.goMainPage();
                }
            }
        }, 1);
        if (adBean != null) {
            String str = systemInfoBean.ad_show_time;
            Intrinsics.checkNotNullExpressionValue(str, "systemInfoBean.ad_show_time");
            int parseInt = Integer.parseInt(str);
            String str2 = systemInfoBean.ad_auto_jump;
            Intrinsics.checkNotNullExpressionValue(str2, "systemInfoBean.ad_auto_jump");
            countDown(parseInt, str2);
            initBannerView(adBean);
            main(adBean);
        }
    }

    private final void showUpdateDialog(final SystemInfoBean systemInfoBean, boolean isMandatoryUpdate) {
        String version = systemInfoBean.version;
        String str = systemInfoBean.version_description;
        if (str == null) {
            str = "";
        }
        String str2 = str;
        Intrinsics.checkNotNullExpressionValue(version, "version");
        Intrinsics.checkNotNullExpressionValue(str2, "if (systemInfoBean.version_description == null) \"\" else systemInfoBean.version_description");
        new UpdateDialog(version, isMandatoryUpdate, str2, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$showUpdateDialog$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                C0840d.a.m174d(C0840d.f235a, SplashActivity.this, systemInfoBean.site_url, null, null, 12);
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$showUpdateDialog$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                String str3 = SystemInfoBean.this.download_url;
                if (!(str3 == null || str3.length() == 0)) {
                    String str4 = SystemInfoBean.this.download_url;
                    Intrinsics.checkNotNullExpressionValue(str4, "systemInfoBean.download_url");
                    if (StringsKt__StringsJVMKt.startsWith$default(str4, "http", false, 2, null)) {
                        String str5 = SystemInfoBean.this.download_url;
                        Intrinsics.checkNotNullExpressionValue(str5, "systemInfoBean.download_url");
                        if (StringsKt__StringsJVMKt.startsWith$default(str5, "https", false, 2, null)) {
                            this.downloadNewVersion(SystemInfoBean.this);
                            return;
                        }
                    }
                }
                C2354n.m2449Z("无效下载地址");
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$showUpdateDialog$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                List<AdBean> list = SystemInfoBean.this.f10031ad;
                if (list == null) {
                    this.goMain();
                    return;
                }
                SplashActivity splashActivity = this;
                Intrinsics.checkNotNullExpressionValue(list, "systemInfoBean.ad");
                splashActivity.showAdView(list, SystemInfoBean.this);
            }
        }).show(getSupportFragmentManager(), "updateDialog");
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        String str;
        int i2 = R$id.tv_email;
        ((BLTextView) findViewById(i2)).setText(C0885h.f329a);
        C2354n.m2374A((BLTextView) findViewById(i2), 0L, new Function1<BLTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashActivity$bindEvent$1
            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(BLTextView bLTextView) {
                C2354n.m2398I(C0885h.f329a);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(BLTextView bLTextView) {
                invoke2(bLTextView);
                return Unit.INSTANCE;
            }
        }, 1);
        ((RecyclerView) findViewById(R$id.f9901rv)).setAdapter(getMAdapter());
        SplashActivity$mAdapter$2.C38921 mAdapter = getMAdapter();
        Intrinsics.checkNotNullParameter("default_sites", "key");
        Intrinsics.checkNotNullParameter("https://douman.net", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String string = sharedPreferences.getString("default_sites", "https://douman.net");
        Intrinsics.checkNotNull(string);
        mAdapter.setNewData(TypeIntrinsics.asMutableList(StringsKt__StringsKt.split$default((CharSequence) string, new String[]{ChineseToPinyinResource.Field.COMMA}, false, 0, 6, (Object) null)));
        ApplicationC2828a context = C2827a.f7670a;
        if (context == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            PackageManager packageManager = context.getPackageManager();
            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
            str = (String) packageManager.getApplicationLabel(applicationInfo);
        } catch (PackageManager.NameNotFoundException unused) {
            str = "";
        }
        if (Intrinsics.areEqual(str != null ? Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(str, "九妖", false, 2, null)) : null, Boolean.TRUE)) {
            C2354n.m2467d2(this).m3297o(Integer.valueOf(R.drawable.launch_image_91)).m3290d0().m757R((ImageView) findViewById(R$id.iv_ADImg));
        } else {
            C2354n.m2467d2(this).m3297o(Integer.valueOf(R.drawable.launch_image_51)).m3290d0().m757R((ImageView) findViewById(R$id.iv_ADImg));
        }
        final SplashViewMode viewModel = getViewModel();
        viewModel.getLineError().observe(this, new Observer() { // from class: b.a.a.a.t.p.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                SplashActivity.m6006bindEvent$lambda6$lambda1(SplashActivity.this, (Boolean) obj);
            }
        });
        viewModel.getLineSuccess().observe(this, new Observer() { // from class: b.a.a.a.t.p.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                SplashActivity.m6007bindEvent$lambda6$lambda2(SplashActivity.this, (Boolean) obj);
            }
        });
        viewModel.getSystemInfoBody().observe(this, new Observer() { // from class: b.a.a.a.t.p.b
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                SplashActivity.m6008bindEvent$lambda6$lambda3(SplashActivity.this, viewModel, (SystemInfoBean) obj);
            }
        });
        viewModel.getSystemCdn().observe(this, new Observer() { // from class: b.a.a.a.t.p.h
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                SplashActivity.m6009bindEvent$lambda6$lambda4(SplashActivity.this, (Boolean) obj);
            }
        });
        viewModel.getPicVerState().observe(this, new Observer() { // from class: b.a.a.a.t.p.c
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                SplashActivity.m6010bindEvent$lambda6$lambda5(SplashViewMode.this, (Boolean) obj);
            }
        });
    }

    @NotNull
    public final Banner<?, ?> getBanner_splash() {
        return (Banner) this.banner_splash.getValue();
    }

    public final int getCdnLengh() {
        return this.cdnLengh;
    }

    public final int getCheckCdnPosition() {
        return this.checkCdnPosition;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.splash_act;
    }

    @NotNull
    public final List<List<AdBean>> getMBanners2() {
        return this.mBanners2;
    }

    @NotNull
    public final SystemInfoBean getMSystemInfoBean() {
        SystemInfoBean systemInfoBean = this.mSystemInfoBean;
        if (systemInfoBean != null) {
            return systemInfoBean;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mSystemInfoBean");
        throw null;
    }

    public final void goMain() {
        Intrinsics.checkNotNullParameter("enter_app", "act");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("act", "enter_app");
        C0917a.m221e(C0917a.f372a, "system/doLogs", Object.class, linkedHashMap, C0846g.f248c, null, false, false, null, false, 432);
        IndexActivity.Companion.start$default(IndexActivity.INSTANCE, this, null, false, 6, null);
        finish();
    }

    @NotNull
    public final InterfaceC3053d1 main(@NotNull List<? extends AdBean> adBean) {
        AbstractC3091q0 abstractC3091q0;
        CoroutineContext plus;
        Intrinsics.checkNotNullParameter(adBean, "adBean");
        Function2 splashActivity$main$1 = new SplashActivity$main$1(adBean, this, null);
        CoroutineContext coroutineContext = EmptyCoroutineContext.INSTANCE;
        Thread currentThread = Thread.currentThread();
        ContinuationInterceptor.Companion companion = ContinuationInterceptor.INSTANCE;
        ContinuationInterceptor continuationInterceptor = (ContinuationInterceptor) coroutineContext.get(companion);
        if (continuationInterceptor == null) {
            C3107v1 c3107v1 = C3107v1.f8468b;
            abstractC3091q0 = C3107v1.m3642a();
            plus = coroutineContext.plus(coroutineContext.plus(abstractC3091q0));
            AbstractC3036c0 abstractC3036c0 = C3079m0.f8430a;
            if (plus != abstractC3036c0 && plus.get(companion) == null) {
                plus = plus.plus(abstractC3036c0);
            }
        } else {
            if (!(continuationInterceptor instanceof AbstractC3091q0)) {
                continuationInterceptor = null;
            }
            C3107v1 c3107v12 = C3107v1.f8468b;
            abstractC3091q0 = C3107v1.f8467a.get();
            plus = coroutineContext.plus(coroutineContext);
            AbstractC3036c0 abstractC3036c02 = C3079m0.f8430a;
            if (plus != abstractC3036c02 && plus.get(companion) == null) {
                plus = plus.plus(abstractC3036c02);
            }
        }
        C3054e c3054e = new C3054e(plus, currentThread, abstractC3091q0);
        c3054e.m3512m0(1, c3054e, splashActivity$main$1);
        AbstractC3091q0 abstractC3091q02 = c3054e.f8396h;
        if (abstractC3091q02 != null) {
            int i2 = AbstractC3091q0.f8440c;
            abstractC3091q02.m3629X(false);
        }
        while (!Thread.interrupted()) {
            try {
                AbstractC3091q0 abstractC3091q03 = c3054e.f8396h;
                long mo3631Z = abstractC3091q03 != null ? abstractC3091q03.mo3631Z() : Long.MAX_VALUE;
                if (!(c3054e.m3576L() instanceof InterfaceC3115y0)) {
                    Object m3618a = C3071j1.m3618a(c3054e.m3576L());
                    C3108w c3108w = (C3108w) (m3618a instanceof C3108w ? m3618a : null);
                    if (c3108w == null) {
                        return (InterfaceC3053d1) m3618a;
                    }
                    throw c3108w.f8470b;
                }
                LockSupport.parkNanos(c3054e, mo3631Z);
            } finally {
                AbstractC3091q0 abstractC3091q04 = c3054e.f8396h;
                if (abstractC3091q04 != null) {
                    int i3 = AbstractC3091q0.f8440c;
                    abstractC3091q04.m3626U(false);
                }
            }
        }
        InterruptedException interruptedException = new InterruptedException();
        c3054e.m3592w(interruptedException);
        throw interruptedException;
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 10010) {
            StringBuilder sb = new StringBuilder();
            MyApp myApp = MyApp.f9891f;
            File externalFilesDir = MyApp.m4183d().getExternalFilesDir("apk");
            Intrinsics.checkNotNull(externalFilesDir);
            String absolutePath = externalFilesDir.getAbsolutePath();
            Intrinsics.checkNotNullExpressionValue(absolutePath, "MyApp.instance.getExternalFilesDir(\"apk\")!!.absolutePath");
            sb.append(absolutePath);
            sb.append((Object) File.separator);
            sb.append("new.apk");
            grantedInstallApk(sb.toString());
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (isTaskRoot()) {
            return;
        }
        finish();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void releaseResources() {
        super.releaseResources();
        cancelJob(this.jobCountDown);
    }

    public final void setCdnLengh(int i2) {
        this.cdnLengh = i2;
    }

    public final void setCheckCdnPosition(int i2) {
        this.checkCdnPosition = i2;
    }

    public final void setMBanners2(@NotNull List<List<AdBean>> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.mBanners2 = list;
    }

    public final void setMSystemInfoBean(@NotNull SystemInfoBean systemInfoBean) {
        Intrinsics.checkNotNullParameter(systemInfoBean, "<set-?>");
        this.mSystemInfoBean = systemInfoBean;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public SplashViewMode viewModelInstance() {
        return getViewModel();
    }
}
