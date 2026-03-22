package com.jbzd.media.movecartoons.p396ui.search.child;

import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.child.SearchResultListLong;
import com.jbzd.media.movecartoons.p396ui.search.model.SearchResultModel;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseViewModelFragment;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\\\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000b\u0018\u0000 22\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00012B\u0007¢\u0006\u0004\b1\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005JC\u0010\r\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u00062\"\u0010\n\u001a\u001e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00060\bj\u000e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0006`\t2\u0006\u0010\f\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0012\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0012\u0010\u0013J\u000f\u0010\u0014\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0014\u0010\u0005J\u000f\u0010\u0015\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0015\u0010\u0005R\u001d\u0010\u001b\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0018\u001a\u0004\b\u0019\u0010\u001aR)\u0010\u001f\u001a\u0012\u0012\u0004\u0012\u00020\u001d0\u001cj\b\u0012\u0004\u0012\u00020\u001d`\u001e8\u0006@\u0006¢\u0006\f\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\"R\u001d\u0010'\u001a\u00020#8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u0018\u001a\u0004\b%\u0010&R\u001d\u0010,\u001a\u00020(8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0018\u001a\u0004\b*\u0010+R\u001d\u0010/\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0018\u001a\u0004\b.\u0010\u0010R&\u00100\u001a\u0012\u0012\u0004\u0012\u00020\u00060\u001cj\b\u0012\u0004\u0012\u00020\u0006`\u001e8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b0\u0010 ¨\u00063"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/SearchBottomVideosFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/search/model/SearchResultModel;", "", "setPager", "()V", "", "name", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "body", "", "isShort", "addFragment", "(Ljava/lang/String;Ljava/util/HashMap;Z)V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/SearchResultModel;", "", "getLayout", "()I", "onDestroyView", "initViews", "Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout$delegate", "Lkotlin/Lazy;", "getTabLayout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "mFragments", "Ljava/util/ArrayList;", "getMFragments", "()Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "mAdapter$delegate", "getMAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "mAdapter", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "viewModel$delegate", "getViewModel", "viewModel", "tabNames", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchBottomVideosFragment extends BaseViewModelFragment<SearchResultModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: mAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mAdapter;

    @NotNull
    private final ArrayList<Fragment> mFragments;

    /* renamed from: tabLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout;

    @NotNull
    private final ArrayList<String> tabNames;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ7\u0010\u0007\u001a\u00020\u00062(\b\u0002\u0010\u0005\u001a\"\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/SearchBottomVideosFragment$Companion;", "", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "map", "Landroidx/fragment/app/Fragment;", "newInstance", "(Ljava/util/HashMap;)Landroidx/fragment/app/Fragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ Fragment newInstance$default(Companion companion, HashMap hashMap, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                hashMap = null;
            }
            return companion.newInstance(hashMap);
        }

        @NotNull
        public final Fragment newInstance(@Nullable HashMap<String, String> map) {
            SearchBottomVideosFragment searchBottomVideosFragment = new SearchBottomVideosFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("params_map", map);
            Unit unit = Unit.INSTANCE;
            searchBottomVideosFragment.setArguments(bundle);
            return searchBottomVideosFragment;
        }
    }

    public SearchBottomVideosFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchBottomVideosFragment$special$$inlined$viewModels$default$1
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Fragment invoke() {
                return Fragment.this;
            }
        };
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(SearchResultModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchBottomVideosFragment$special$$inlined$viewModels$default$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewModelStore invoke() {
                ViewModelStore viewModelStore = ((ViewModelStoreOwner) Function0.this.invoke()).getViewModelStore();
                Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "ownerProducer().viewModelStore");
                return viewModelStore;
            }
        }, null);
        this.tabNames = new ArrayList<>();
        this.mFragments = new ArrayList<>();
        this.mAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchBottomVideosFragment$mAdapter$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewPagerAdapter invoke() {
                FragmentManager childFragmentManager = SearchBottomVideosFragment.this.getChildFragmentManager();
                Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
                return new ViewPagerAdapter(childFragmentManager, SearchBottomVideosFragment.this.getMFragments(), 0, 4, null);
            }
        });
        this.vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchBottomVideosFragment$vp_content$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewPager invoke() {
                View view = SearchBottomVideosFragment.this.getView();
                ViewPager viewPager = view == null ? null : (ViewPager) view.findViewById(R.id.vp_content);
                Intrinsics.checkNotNull(viewPager);
                return viewPager;
            }
        });
        this.tabLayout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchBottomVideosFragment$tabLayout$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final SlidingTabLayout invoke() {
                View view = SearchBottomVideosFragment.this.getView();
                SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout);
                Intrinsics.checkNotNull(slidingTabLayout);
                return slidingTabLayout;
            }
        });
    }

    private final void addFragment(String name, HashMap<String, String> body, boolean isShort) {
        this.tabNames.add(0, name);
        this.mFragments.add(0, SearchResultListLong.Companion.newInstance$default(SearchResultListLong.INSTANCE, body, false, 2, null));
    }

    private final ViewPagerAdapter getMAdapter() {
        return (ViewPagerAdapter) this.mAdapter.getValue();
    }

    private final void setPager() {
        ViewPager vp_content = getVp_content();
        vp_content.setOffscreenPageLimit(getMFragments().size());
        vp_content.setAdapter(getMAdapter());
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchBottomVideosFragment$setPager$1$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
            }
        });
        getTabLayout().setIndicatorHeight(4.0f);
        getTabLayout().setIndicatorWidth(10.0f);
        SlidingTabLayout tabLayout = getTabLayout();
        ViewPager vp_content2 = getVp_content();
        Object[] array = this.tabNames.toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tabLayout.m4011e(vp_content2, (String[]) array);
        if (this.tabNames.size() < 2) {
            getTabLayout().setVisibility(8);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_search_bottom;
    }

    @NotNull
    public final ArrayList<Fragment> getMFragments() {
        return this.mFragments;
    }

    @NotNull
    public final SlidingTabLayout getTabLayout() {
        return (SlidingTabLayout) this.tabLayout.getValue();
    }

    @NotNull
    public final SearchResultModel getViewModel() {
        return (SearchResultModel) this.viewModel.getValue();
    }

    @NotNull
    public final ViewPager getVp_content() {
        return (ViewPager) this.vp_content.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getViewModel();
        Bundle arguments = getArguments();
        Serializable serializable = arguments == null ? null : arguments.getSerializable("params_map");
        Objects.requireNonNull(serializable, "null cannot be cast to non-null type java.util.HashMap<kotlin.String, kotlin.String>{ kotlin.collections.TypeAliasesKt.HashMap<kotlin.String, kotlin.String> }");
        addFragment("长视频", (HashMap) serializable, false);
        setPager();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public SearchResultModel viewModelInstance() {
        return getViewModel();
    }
}
