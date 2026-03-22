package com.jbzd.media.movecartoons.p396ui.search.page;

import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment;
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
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 &2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001&B\u0007¢\u0006\u0004\b%\u0010\nJ\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nJ\r\u0010\u000b\u001a\u00020\b¢\u0006\u0004\b\u000b\u0010\nJ9\u0010\u0011\u001a\u00020\b2\u0006\u0010\r\u001a\u00020\f2\"\u0010\u0010\u001a\u001e\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\f0\u000ej\u000e\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\f`\u000f¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\bH\u0016¢\u0006\u0004\b\u0013\u0010\nR)\u0010\u0017\u001a\u0012\u0012\u0004\u0012\u00020\u00150\u0014j\b\u0012\u0004\u0012\u00020\u0015`\u00168\u0006@\u0006¢\u0006\f\n\u0004\b\u0017\u0010\u0018\u001a\u0004\b\u0019\u0010\u001aR&\u0010\u001b\u001a\u0012\u0012\u0004\u0012\u00020\f0\u0014j\b\u0012\u0004\u0012\u00020\f`\u00168\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001b\u0010\u0018R\u001d\u0010\u001f\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u001d\u001a\u0004\b\u001e\u0010\u0004R\u001d\u0010$\u001a\u00020 8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u001d\u001a\u0004\b\"\u0010#¨\u0006'"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/page/SearchPostFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/search/model/SearchResultModel;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/SearchResultModel;", "", "getLayout", "()I", "", "onDestroyView", "()V", "setPager", "", "name", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "body", "addFragment", "(Ljava/lang/String;Ljava/util/HashMap;)V", "initViews", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "mFragments", "Ljava/util/ArrayList;", "getMFragments", "()Ljava/util/ArrayList;", "tabNames", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "mAdapter$delegate", "getMAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "mAdapter", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchPostFragment extends BaseViewModelFragment<SearchResultModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: mAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mAdapter;

    @NotNull
    private final ArrayList<Fragment> mFragments;

    @NotNull
    private final ArrayList<String> tabNames;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/page/SearchPostFragment$Companion;", "", "Landroidx/fragment/app/Fragment;", "newInstance", "()Landroidx/fragment/app/Fragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Fragment newInstance() {
            return new SearchPostFragment();
        }
    }

    public SearchPostFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchPostFragment$special$$inlined$viewModels$default$1
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
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(SearchResultModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchPostFragment$special$$inlined$viewModels$default$2
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
        this.mAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchPostFragment$mAdapter$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewPagerAdapter invoke() {
                FragmentManager childFragmentManager = SearchPostFragment.this.getChildFragmentManager();
                Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
                return new ViewPagerAdapter(childFragmentManager, SearchPostFragment.this.getMFragments(), 0, 4, null);
            }
        });
    }

    private final ViewPagerAdapter getMAdapter() {
        return (ViewPagerAdapter) this.mAdapter.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public final void addFragment(@NotNull String name, @NotNull HashMap<String, String> body) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(body, "body");
        this.tabNames.add(0, name);
        this.mFragments.add(0, CommonPostListFragment.INSTANCE.newInstance(body, false, ""));
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
    public final SearchResultModel getViewModel() {
        return (SearchResultModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getViewModel();
        Bundle arguments = getArguments();
        Serializable serializable = arguments == null ? null : arguments.getSerializable("params_map");
        Objects.requireNonNull(serializable, "null cannot be cast to non-null type java.util.HashMap<kotlin.String, kotlin.String>{ kotlin.collections.TypeAliasesKt.HashMap<kotlin.String, kotlin.String> }");
        addFragment("帖子", (HashMap) serializable);
        setPager();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
    }

    public final void setPager() {
        View view = getView();
        ViewPager viewPager = (ViewPager) (view == null ? null : view.findViewById(R$id.vp_content));
        viewPager.setOffscreenPageLimit(getMFragments().size());
        viewPager.setAdapter(getMAdapter());
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchPostFragment$setPager$1$1
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
        View view2 = getView();
        ((SlidingTabLayout) (view2 == null ? null : view2.findViewById(R$id.tabLayout))).setIndicatorHeight(4.0f);
        View view3 = getView();
        ((SlidingTabLayout) (view3 == null ? null : view3.findViewById(R$id.tabLayout))).setIndicatorWidth(10.0f);
        View view4 = getView();
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) (view4 == null ? null : view4.findViewById(R$id.tabLayout));
        View view5 = getView();
        View findViewById = view5 == null ? null : view5.findViewById(R$id.vp_content);
        Object[] array = this.tabNames.toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e((ViewPager) findViewById, (String[]) array);
        if (this.tabNames.size() < 2) {
            View view6 = getView();
            ((SlidingTabLayout) (view6 != null ? view6.findViewById(R$id.tabLayout) : null)).setVisibility(8);
        }
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public SearchResultModel viewModelInstance() {
        return getViewModel();
    }
}
