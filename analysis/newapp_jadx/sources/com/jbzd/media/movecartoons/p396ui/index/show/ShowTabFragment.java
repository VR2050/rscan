package com.jbzd.media.movecartoons.p396ui.index.show;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.show.ShortListFragment;
import com.jbzd.media.movecartoons.p396ui.index.show.ShowTabFragment;
import com.jbzd.media.movecartoons.p396ui.index.show.ShowTabFragment$mFilterAdapter$1;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationH;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import com.youth.banner.listener.OnPageChangeListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000E\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0003\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\b\u0007*\u0001\u0015\u0018\u0000 !2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001!B\u0007¢\u0006\u0004\b \u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\t\u0010\u0005R\u001d\u0010\u000f\u001a\u00020\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR\u001f\u0010\u0014\u001a\u0004\u0018\u00010\u00108B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\f\u001a\u0004\b\u0012\u0010\u0013R\u0016\u0010\u0016\u001a\u00020\u00158\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0016\u0010\u0017RA\u0010\u001f\u001a&\u0012\f\u0012\n \u001a*\u0004\u0018\u00010\u00190\u0019 \u001a*\u0012\u0012\f\u0012\n \u001a*\u0004\u0018\u00010\u00190\u0019\u0018\u00010\u001b0\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\f\u001a\u0004\b\u001d\u0010\u001e¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/show/ShowTabFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "initBannerView", "()V", "", "getLayout", "()I", "initViews", "Lcom/jbzd/media/movecartoons/ui/index/show/ShortListFragment;", "mFragment$delegate", "Lkotlin/Lazy;", "getMFragment", "()Lcom/jbzd/media/movecartoons/ui/index/show/ShortListFragment;", "mFragment", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "com/jbzd/media/movecartoons/ui/index/show/ShowTabFragment$mFilterAdapter$1", "mFilterAdapter", "Lcom/jbzd/media/movecartoons/ui/index/show/ShowTabFragment$mFilterAdapter$1;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "kotlin.jvm.PlatformType", "", "mBanners$delegate", "getMBanners", "()Ljava/util/List;", "mBanners", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShowTabFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String key_tab = "tab_bean";

    @NotNull
    private final ShowTabFragment$mFilterAdapter$1 mFilterAdapter;

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowTabFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = ShowTabFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable("tab_bean"));
        }
    });

    /* renamed from: mFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFragment = LazyKt__LazyJVMKt.lazy(new Function0<ShortListFragment>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowTabFragment$mFragment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ShortListFragment invoke() {
            MainMenusBean mTabBean;
            ShortListFragment.Companion companion = ShortListFragment.INSTANCE;
            mTabBean = ShowTabFragment.this.getMTabBean();
            return companion.newInstance(mTabBean);
        }
    });

    /* renamed from: mBanners$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mBanners = LazyKt__LazyJVMKt.lazy(new Function0<List<AdBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowTabFragment$mBanners$2
        @Override // kotlin.jvm.functions.Function0
        public final List<AdBean> invoke() {
            MyApp myApp = MyApp.f9891f;
            return MyApp.m4185f().shallow_index_banner;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\b\u001a\u00020\u00078\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\b\u0010\t¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/show/ShowTabFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "Lcom/jbzd/media/movecartoons/ui/index/show/ShowTabFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;)Lcom/jbzd/media/movecartoons/ui/index/show/ShowTabFragment;", "", "key_tab", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final ShowTabFragment newInstance(@Nullable MainMenusBean tabBean) {
            ShowTabFragment showTabFragment = new ShowTabFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("tab_bean", tabBean);
            Unit unit = Unit.INSTANCE;
            showTabFragment.setArguments(bundle);
            return showTabFragment;
        }
    }

    public ShowTabFragment() {
        final ShowTabFragment$mFilterAdapter$1 showTabFragment$mFilterAdapter$1 = new ShowTabFragment$mFilterAdapter$1();
        showTabFragment$mFilterAdapter$1.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.n.c
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                ShowTabFragment.m5859mFilterAdapter$lambda1$lambda0(ShowTabFragment$mFilterAdapter$1.this, this, baseQuickAdapter, view, i2);
            }
        });
        Unit unit = Unit.INSTANCE;
        this.mFilterAdapter = showTabFragment$mFilterAdapter$1;
    }

    private final List<AdBean> getMBanners() {
        return (List) this.mBanners.getValue();
    }

    private final ShortListFragment getMFragment() {
        return (ShortListFragment) this.mFragment.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MainMenusBean getMTabBean() {
        return (MainMenusBean) this.mTabBean.getValue();
    }

    private final void initBannerView() {
        List<AdBean> mBanners = getMBanners();
        if (mBanners == null || mBanners.isEmpty()) {
            View view = getView();
            ((ScaleRelativeLayout) (view == null ? null : view.findViewById(R$id.banner_parent))).setVisibility(8);
        } else {
            View view2 = getView();
            ((ScaleRelativeLayout) (view2 == null ? null : view2.findViewById(R$id.banner_parent))).setVisibility(0);
            View view3 = getView();
            Banner banner = (Banner) (view3 == null ? null : view3.findViewById(R$id.banner));
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
            banner.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.g.n.b
                @Override // com.youth.banner.listener.OnBannerListener
                public final void OnBannerClick(Object obj, int i2) {
                    ShowTabFragment.m5856initBannerView$lambda8$lambda7(ShowTabFragment.this, obj, i2);
                }
            });
            banner.setIndicator(new RectangleIndicator(requireContext()));
            banner.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowTabFragment$initBannerView$1$3
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
        View view4 = getView();
        ((ScaleRelativeLayout) (view4 != null ? view4.findViewById(R$id.banner_parent) : null)).setVisibility(8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBannerView$lambda-8$lambda-7, reason: not valid java name */
    public static final void m5856initBannerView$lambda8$lambda7(ShowTabFragment this$0, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C0840d.a aVar = C0840d.f235a;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        AdBean adBean = this$0.getMBanners().get(i2);
        Intrinsics.checkNotNullExpressionValue(adBean, "mBanners[position]");
        aVar.m176b(requireContext, adBean);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-2, reason: not valid java name */
    public static final void m5857initViews$lambda2(ShowTabFragment this$0, AppBarLayout appBarLayout, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        View view = this$0.getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setEnabled(i2 == 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-4$lambda-3, reason: not valid java name */
    public static final void m5858initViews$lambda4$lambda3(ShowTabFragment this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getMFragment().refresh();
        View view = this$0.getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: mFilterAdapter$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5859mFilterAdapter$lambda1$lambda0(ShowTabFragment$mFilterAdapter$1 this_apply, ShowTabFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        TagBean tagBean;
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        if (this_apply.getSelectedPosition() == i2) {
            Object first = CollectionsKt___CollectionsKt.first((List<? extends Object>) adapter.getData());
            Objects.requireNonNull(first, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
            tagBean = (TagBean) first;
        } else {
            Object obj = adapter.getData().get(i2);
            Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
            tagBean = (TagBean) obj;
        }
        this$0.getMFragment().updateIds(tagBean.value, tagBean.key);
        this_apply.setSelectedPosition(i2);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_show_tab;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getChildFragmentManager().beginTransaction().replace(R.id.frag_content, getMFragment()).commit();
        View view = getView();
        ((AppBarLayout) (view == null ? null : view.findViewById(R$id.app_bar_layout))).addOnOffsetChangedListener(new AppBarLayout.OnOffsetChangedListener() { // from class: b.a.a.a.t.g.n.a
            @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
            public final void onOffsetChanged(AppBarLayout appBarLayout, int i2) {
                ShowTabFragment.m5857initViews$lambda2(ShowTabFragment.this, appBarLayout, i2);
            }
        });
        View view2 = getView();
        SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) (view2 == null ? null : view2.findViewById(R$id.swipeLayout));
        swipeRefreshLayout.setColorSchemeColors(swipeRefreshLayout.getResources().getColor(R.color.colorAccent));
        swipeRefreshLayout.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() { // from class: b.a.a.a.t.g.n.d
            @Override // androidx.swiperefreshlayout.widget.SwipeRefreshLayout.OnRefreshListener
            public final void onRefresh() {
                ShowTabFragment.m5858initViews$lambda4$lambda3(ShowTabFragment.this);
            }
        });
        View view3 = getView();
        RecyclerView recyclerView = (RecyclerView) (view3 != null ? view3.findViewById(R$id.rv_filter) : null);
        recyclerView.setLayoutManager(new LinearLayoutManager(requireActivity(), 0, false));
        if (recyclerView.getItemDecorationCount() == 0) {
            recyclerView.addItemDecoration(new ItemDecorationH(C2354n.m2425R(requireContext(), 10.0f), C2354n.m2425R(requireContext(), 10.0f)));
        }
        recyclerView.setAdapter(this.mFilterAdapter);
        initBannerView();
    }
}
