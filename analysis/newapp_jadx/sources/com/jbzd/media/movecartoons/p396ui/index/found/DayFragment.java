package com.jbzd.media.movecartoons.p396ui.index.found;

import android.content.Context;
import android.view.View;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.found.DayFragment;
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
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0840d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 \u00192\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001\u0019B\u0007¢\u0006\u0004\b\u0018\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\t\u0010\u0005RA\u0010\u0012\u001a&\u0012\f\u0012\n \f*\u0004\u0018\u00010\u000b0\u000b \f*\u0012\u0012\f\u0012\n \f*\u0004\u0018\u00010\u000b0\u000b\u0018\u00010\r0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0017\u001a\u00020\u00138B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u000f\u001a\u0004\b\u0015\u0010\u0016¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/DayFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "initBannerView", "()V", "", "getLayout", "()I", "initViews", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "kotlin.jvm.PlatformType", "", "mBanners$delegate", "Lkotlin/Lazy;", "getMBanners", "()Ljava/util/List;", "mBanners", "Lcom/jbzd/media/movecartoons/ui/index/found/DayPickListFragment;", "mFragment$delegate", "getMFragment", "()Lcom/jbzd/media/movecartoons/ui/index/found/DayPickListFragment;", "mFragment", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DayFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: mFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFragment = LazyKt__LazyJVMKt.lazy(new Function0<DayPickListFragment>() { // from class: com.jbzd.media.movecartoons.ui.index.found.DayFragment$mFragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final DayPickListFragment invoke() {
            return DayPickListFragment.INSTANCE.newInstance();
        }
    });

    /* renamed from: mBanners$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mBanners = LazyKt__LazyJVMKt.lazy(new Function0<List<AdBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.found.DayFragment$mBanners$2
        @Override // kotlin.jvm.functions.Function0
        public final List<AdBean> invoke() {
            MyApp myApp = MyApp.f9891f;
            return MyApp.m4185f().find_banner;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/DayFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/found/DayFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/found/DayFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final DayFragment newInstance() {
            return new DayFragment();
        }
    }

    private final List<AdBean> getMBanners() {
        return (List) this.mBanners.getValue();
    }

    private final DayPickListFragment getMFragment() {
        return (DayPickListFragment) this.mFragment.getValue();
    }

    private final void initBannerView() {
        List<AdBean> mBanners = getMBanners();
        if (mBanners == null || mBanners.isEmpty()) {
            View view = getView();
            ((ScaleRelativeLayout) (view != null ? view.findViewById(R$id.banner_parent) : null)).setVisibility(8);
            return;
        }
        View view2 = getView();
        ((ScaleRelativeLayout) (view2 == null ? null : view2.findViewById(R$id.banner_parent))).setVisibility(0);
        View view3 = getView();
        Banner banner = (Banner) (view3 != null ? view3.findViewById(R$id.banner) : null);
        banner.setIntercept(getMBanners().size() != 1);
        Banner addBannerLifecycleObserver = banner.addBannerLifecycleObserver(this);
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        List<AdBean> mBanners2 = getMBanners();
        Intrinsics.checkNotNullExpressionValue(mBanners2, "mBanners");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(mBanners2, 10));
        Iterator<T> it = mBanners2.iterator();
        while (it.hasNext()) {
            arrayList.add(((AdBean) it.next()).content);
        }
        addBannerLifecycleObserver.setAdapter(new BannerAdapterImp(requireContext, arrayList, 0.0f, ShadowDrawableWrapper.COS_45, null, 20));
        banner.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.g.j.b
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                DayFragment.m5817initBannerView$lambda5$lambda4(DayFragment.this, obj, i2);
            }
        });
        banner.setIndicator(new RectangleIndicator(requireContext()));
        banner.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.found.DayFragment$initBannerView$1$3
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
    /* renamed from: initBannerView$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5817initBannerView$lambda5$lambda4(DayFragment this$0, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C0840d.a aVar = C0840d.f235a;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        AdBean adBean = this$0.getMBanners().get(i2);
        Intrinsics.checkNotNullExpressionValue(adBean, "mBanners[position]");
        aVar.m176b(requireContext, adBean);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-0, reason: not valid java name */
    public static final void m5818initViews$lambda0(DayFragment this$0, AppBarLayout appBarLayout, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        View view = this$0.getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setEnabled(i2 == 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5819initViews$lambda2$lambda1(DayFragment this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getMFragment().refresh();
        View view = this$0.getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(false);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_found_day;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getChildFragmentManager().beginTransaction().replace(R.id.frag_content, getMFragment()).commit();
        View view = getView();
        ((AppBarLayout) (view == null ? null : view.findViewById(R$id.app_bar_layout))).addOnOffsetChangedListener(new AppBarLayout.OnOffsetChangedListener() { // from class: b.a.a.a.t.g.j.a
            @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
            public final void onOffsetChanged(AppBarLayout appBarLayout, int i2) {
                DayFragment.m5818initViews$lambda0(DayFragment.this, appBarLayout, i2);
            }
        });
        View view2 = getView();
        SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) (view2 != null ? view2.findViewById(R$id.swipeLayout) : null);
        swipeRefreshLayout.setColorSchemeColors(swipeRefreshLayout.getResources().getColor(R.color.colorAccent));
        swipeRefreshLayout.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() { // from class: b.a.a.a.t.g.j.c
            @Override // androidx.swiperefreshlayout.widget.SwipeRefreshLayout.OnRefreshListener
            public final void onRefresh() {
                DayFragment.m5819initViews$lambda2$lambda1(DayFragment.this);
            }
        });
        initBannerView();
    }
}
