package com.jbzd.media.movecartoons.p396ui.index.found;

import android.text.TextUtils;
import android.view.View;
import android.widget.LinearLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.web.WebFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\b\u000b\u0018\u0000 *2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001*B\u0007¢\u0006\u0004\b)\u0010\u0012J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0006\u0010\u0005J\u0017\u0010\n\u001a\u00020\t2\b\u0010\b\u001a\u0004\u0018\u00010\u0007¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\r\u001a\u00020\t2\b\u0010\f\u001a\u0004\u0018\u00010\u0007¢\u0006\u0004\b\r\u0010\u000bJ\r\u0010\u000f\u001a\u00020\u000e¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0011\u0010\u0012R-\u0010\u001a\u001a\u0012\u0012\u0004\u0012\u00020\u00140\u0013j\b\u0012\u0004\u0012\u00020\u0014`\u00158B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0017\u001a\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001f\u001a\u00020\u001b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0017\u001a\u0004\b\u001d\u0010\u001eR#\u0010$\u001a\b\u0012\u0004\u0012\u00020\u00020 8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u0017\u001a\u0004\b\"\u0010#R+\u0010(\u001a\u0010\u0012\f\u0012\n %*\u0004\u0018\u00010\u00070\u00070 8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u0017\u001a\u0004\b'\u0010#¨\u0006+"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/FoundFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getDefaultTabPosition", "()I", "getLayout", "", "tabId", "", "showTab", "(Ljava/lang/String;)V", "type", "goTabByType", "", "canGoBackAct", "()Z", "initViews", "()V", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "Lkotlin/collections/ArrayList;", "tabEntityBeans$delegate", "Lkotlin/Lazy;", "getTabEntityBeans", "()Ljava/util/ArrayList;", "tabEntityBeans", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "", "fragments$delegate", "getFragments", "()Ljava/util/List;", "fragments", "kotlin.jvm.PlatformType", "tabEntities$delegate", "getTabEntities", "tabEntities", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class FoundFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.found.FoundFragment$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            List fragments;
            FragmentManager childFragmentManager = FoundFragment.this.getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
            fragments = FoundFragment.this.getFragments();
            return new ViewPagerAdapter(childFragmentManager, (ArrayList) fragments, 0, 4, null);
        }
    });

    /* renamed from: tabEntityBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntityBeans = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MainMenusBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.found.FoundFragment$tabEntityBeans$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<MainMenusBean> invoke() {
            ArrayList<MainMenusBean> arrayList = new ArrayList<>();
            MainMenusBean mainMenusBean = new MainMenusBean();
            mainMenusBean.name = "全部";
            mainMenusBean.isAll = true;
            Unit unit = Unit.INSTANCE;
            arrayList.add(mainMenusBean);
            MyApp myApp = MyApp.f9891f;
            List<MainMenusBean> list = MyApp.m4185f().find_tabs;
            if (C2354n.m2414N0(list)) {
                arrayList.addAll(list);
            }
            return arrayList;
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends String>>() { // from class: com.jbzd.media.movecartoons.ui.index.found.FoundFragment$tabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends String> invoke() {
            ArrayList tabEntityBeans;
            tabEntityBeans = FoundFragment.this.getTabEntityBeans();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntityBeans, 10));
            Iterator it = tabEntityBeans.iterator();
            while (it.hasNext()) {
                arrayList.add(((MainMenusBean) it.next()).name);
            }
            return arrayList;
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends Object>>() { // from class: com.jbzd.media.movecartoons.ui.index.found.FoundFragment$fragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends Object> invoke() {
            ArrayList<MainMenusBean> tabEntityBeans;
            tabEntityBeans = FoundFragment.this.getTabEntityBeans();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntityBeans, 10));
            for (MainMenusBean mainMenusBean : tabEntityBeans) {
                arrayList.add(mainMenusBean.isDayPicks() ? DayFragment.Companion.newInstance() : mainMenusBean.isPickCollection() ? PickGroupFragment.INSTANCE.newInstance() : mainMenusBean.isWEB() ? WebFragment.INSTANCE.newInstance(mainMenusBean.link) : Unit.INSTANCE);
            }
            return arrayList;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/FoundFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/found/FoundFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/found/FoundFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final FoundFragment newInstance() {
            return new FoundFragment();
        }
    }

    private final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    private final int getDefaultTabPosition() {
        Iterator<MainMenusBean> it = getTabEntityBeans().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (it.next().isDefaultTab()) {
                return i2;
            }
            i2 = i3;
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<Object> getFragments() {
        return (List) this.fragments.getValue();
    }

    private final List<String> getTabEntities() {
        return (List) this.tabEntities.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<MainMenusBean> getTabEntityBeans() {
        return (ArrayList) this.tabEntityBeans.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public final boolean canGoBackAct() {
        ViewPagerAdapter adapter = getAdapter();
        View view = getView();
        Fragment fragment = adapter.getFragment(((ViewPager) (view == null ? null : view.findViewById(R$id.vp_content))).getCurrentItem());
        if (fragment instanceof WebFragment) {
            return ((WebFragment) fragment).goBackAct();
        }
        return true;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_found;
    }

    public final void goTabByType(@Nullable String type) {
        Iterator<MainMenusBean> it = getTabEntityBeans().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().type, type)) {
                View view = getView();
                ((ViewPager) (view == null ? null : view.findViewById(R$id.vp_content))).setCurrentItem(i2);
                return;
            }
            i2 = i3;
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        int statusBarHeight = ImmersionBar.getStatusBarHeight(this);
        View view = getView();
        ((LinearLayout) (view == null ? null : view.findViewById(R$id.ll_top))).setPadding(0, statusBarHeight, 0, 0);
        View view2 = getView();
        ViewPager viewPager = (ViewPager) (view2 == null ? null : view2.findViewById(R$id.vp_content));
        viewPager.setOffscreenPageLimit(getTabEntities().size());
        viewPager.setAdapter(getAdapter());
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.found.FoundFragment$initViews$1$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                View view3 = FoundFragment.this.getView();
                ((SlidingTabLayout) (view3 == null ? null : view3.findViewById(R$id.tabLayout))).setCurrentTab(position);
            }
        });
        View view3 = getView();
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) (view3 == null ? null : view3.findViewById(R$id.tabLayout));
        View view4 = getView();
        View findViewById = view4 == null ? null : view4.findViewById(R$id.vp_content);
        Object[] array = getTabEntities().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e((ViewPager) findViewById, (String[]) array);
        if (!getTabEntities().isEmpty()) {
            View view5 = getView();
            ((ViewPager) (view5 != null ? view5.findViewById(R$id.vp_content) : null)).setCurrentItem(getDefaultTabPosition());
        }
    }

    public final void showTab(@Nullable String tabId) {
        Iterator<MainMenusBean> it = getTabEntityBeans().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().f10030id, tabId)) {
                View view = getView();
                ((ViewPager) (view == null ? null : view.findViewById(R$id.vp_content))).setCurrentItem(i2);
                return;
            }
            i2 = i3;
        }
    }
}
