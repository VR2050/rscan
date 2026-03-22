package com.jbzd.media.movecartoons.p396ui.appstore;

import android.content.Context;
import android.os.Bundle;
import android.widget.ImageView;
import androidx.activity.ComponentActivity;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.AppBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.appstore.AppStoreActivity;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import com.youth.banner.listener.OnPageChangeListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 +2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001+B\u0007¢\u0006\u0004\b*\u0010\u0016J\u001d\u0010\u0007\u001a\u00020\u00062\f\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\r\u0010\t\u001a\u00020\u0002¢\u0006\u0004\b\t\u0010\nJ\u0019\u0010\r\u001a\u00020\u00062\b\u0010\f\u001a\u0004\u0018\u00010\u000bH\u0014¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0013\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001c\u001a\u00020\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001bR%\u0010!\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\u001d8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u0019\u001a\u0004\b\u001f\u0010 R\u001d\u0010&\u001a\u00020\"8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u0019\u001a\u0004\b$\u0010%R\u001d\u0010)\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u0019\u001a\u0004\b(\u0010\n¨\u0006,"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/appstore/AppStoreActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "mBanners", "", "initBannerView", "(Ljava/util/List;)V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "", "getLayoutId", "()I", "", "getTopBarTitle", "()Ljava/lang/String;", "bindEvent", "()V", "Lcom/jbzd/media/movecartoons/ui/appstore/AppListFragment;", "fragment$delegate", "Lkotlin/Lazy;", "getFragment", "()Lcom/jbzd/media/movecartoons/ui/appstore/AppListFragment;", "fragment", "Lcom/youth/banner/Banner;", "banner$delegate", "getBanner", "()Lcom/youth/banner/Banner;", "banner", "Lcom/jbzd/media/movecartoons/view/viewgroup/ScaleRelativeLayout;", "banner_parent$delegate", "getBanner_parent", "()Lcom/jbzd/media/movecartoons/view/viewgroup/ScaleRelativeLayout;", "banner_parent", "viewModel$delegate", "getViewModel", "viewModel", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AppStoreActivity extends MyThemeActivity<MineViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(MineViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppStoreActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppStoreActivity$special$$inlined$viewModels$default$1
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

    /* renamed from: fragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragment = LazyKt__LazyJVMKt.lazy(new Function0<AppListFragment>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppStoreActivity$fragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppListFragment invoke() {
            return AppListFragment.INSTANCE.newInstance(new Function1<List<? extends AdBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppStoreActivity$fragment$2.1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(List<? extends AdBean> list) {
                    invoke2(list);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull List<? extends AdBean> it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            });
        }
    });

    /* renamed from: banner_parent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner_parent = LazyKt__LazyJVMKt.lazy(new Function0<ScaleRelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppStoreActivity$banner_parent$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ScaleRelativeLayout invoke() {
            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) AppStoreActivity.this.findViewById(R.id.banner_parent);
            Intrinsics.checkNotNull(scaleRelativeLayout);
            return scaleRelativeLayout;
        }
    });

    /* renamed from: banner$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner = LazyKt__LazyJVMKt.lazy(new Function0<Banner<?, ?>>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppStoreActivity$banner$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final Banner<?, ?> invoke() {
            Banner<?, ?> banner = (Banner) AppStoreActivity.this.findViewById(R.id.banner);
            Intrinsics.checkNotNull(banner);
            return banner;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/appstore/AppStoreActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, AppStoreActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5745bindEvent$lambda1$lambda0(AppStoreActivity this$0, AppBean appBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        List<AdBean> list = appBean.ads;
        Intrinsics.checkNotNullExpressionValue(list, "it.ads");
        this$0.initBannerView(list);
    }

    private final AppListFragment getFragment() {
        return (AppListFragment) this.fragment.getValue();
    }

    private final MineViewModel getViewModel() {
        return (MineViewModel) this.viewModel.getValue();
    }

    private final void initBannerView(final List<? extends AdBean> mBanners) {
        if (mBanners == null || mBanners.isEmpty()) {
            getBanner_parent().setVisibility(8);
            return;
        }
        getBanner_parent().setVisibility(0);
        final Banner<?, ?> banner = getBanner();
        banner.setIntercept(mBanners.size() != 1);
        Banner addBannerLifecycleObserver = banner.addBannerLifecycleObserver(this);
        Context context = banner.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(mBanners, 10));
        Iterator<T> it = mBanners.iterator();
        while (it.hasNext()) {
            arrayList.add(((AdBean) it.next()).content);
        }
        addBannerLifecycleObserver.setAdapter(new BannerAdapterImp(context, arrayList, 0.0f, ShadowDrawableWrapper.COS_45, ImageView.ScaleType.CENTER_CROP, 4));
        banner.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.b.a
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                AppStoreActivity.m5746initBannerView$lambda4$lambda3(Banner.this, mBanners, obj, i2);
            }
        });
        banner.setIndicator(new RectangleIndicator(banner.getContext()));
        banner.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppStoreActivity$initBannerView$1$3
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
        banner.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBannerView$lambda-4$lambda-3, reason: not valid java name */
    public static final void m5746initBannerView$lambda4$lambda3(Banner this_run, List mBanners, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(mBanners, "$mBanners");
        C0840d.a aVar = C0840d.f235a;
        Context context = this_run.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        aVar.m176b(context, (AdBean) mBanners.get(i2));
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        MineViewModel viewModel = getViewModel();
        getViewModel().appStore(1);
        viewModel.getAppBean().observe(this, new Observer() { // from class: b.a.a.a.t.b.b
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                AppStoreActivity.m5745bindEvent$lambda1$lambda0(AppStoreActivity.this, (AppBean) obj);
            }
        });
    }

    @NotNull
    public final Banner<?, ?> getBanner() {
        return (Banner) this.banner.getValue();
    }

    @NotNull
    public final ScaleRelativeLayout getBanner_parent() {
        return (ScaleRelativeLayout) this.banner_parent.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_app_store;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "应用中心";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getSupportFragmentManager().beginTransaction().replace(R.id.frag_content, getFragment()).commit();
    }

    @NotNull
    public final MineViewModel viewModelInstance() {
        return getViewModel();
    }
}
