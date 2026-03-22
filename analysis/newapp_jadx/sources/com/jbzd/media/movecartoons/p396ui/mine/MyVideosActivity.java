package com.jbzd.media.movecartoons.p396ui.mine;

import android.content.Context;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.mine.MyVideosActivity;
import com.jbzd.media.movecartoons.p396ui.post.PostInputActivity;
import com.jbzd.media.movecartoons.view.page.MyViewPager;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseThemeActivity;
import java.util.ArrayList;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000X\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u0000 42\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00014B\u0007¢\u0006\u0004\b3\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\f\u0010\u0005J\u000f\u0010\r\u001a\u00020\u0003H\u0014¢\u0006\u0004\b\r\u0010\u0005J\r\u0010\u000e\u001a\u00020\u0002¢\u0006\u0004\b\u000e\u0010\u000fR%\u0010\u0016\u001a\n \u0011*\u0004\u0018\u00010\u00100\u00108F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015R%\u0010\u001b\u001a\n \u0011*\u0004\u0018\u00010\u00170\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0013\u001a\u0004\b\u0019\u0010\u001aR\u001d\u0010\u001e\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0013\u001a\u0004\b\u001d\u0010\u000fR2\u0010!\u001a\u0012\u0012\u0004\u0012\u00020\t0\u001fj\b\u0012\u0004\u0012\u00020\t` 8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b!\u0010\"\u001a\u0004\b#\u0010$\"\u0004\b%\u0010&R\u001d\u0010+\u001a\u00020'8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u0013\u001a\u0004\b)\u0010*R%\u00100\u001a\n \u0011*\u0004\u0018\u00010,0,8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0013\u001a\u0004\b.\u0010/R&\u00102\u001a\u0012\u0012\u0004\u0012\u0002010\u001fj\b\u0012\u0004\u0012\u000201` 8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b2\u0010\"¨\u00065"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MyVideosActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "", "bindEvent", "()V", "", "getLayoutId", "()I", "", "getTopBarTitle", "()Ljava/lang/String;", "clickRight", "onResume", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "Landroid/widget/TextView;", "kotlin.jvm.PlatformType", "tv_titleRight$delegate", "Lkotlin/Lazy;", "getTv_titleRight", "()Landroid/widget/TextView;", "tv_titleRight", "Lcom/jbzd/media/movecartoons/view/page/MyViewPager;", "vp_content$delegate", "getVp_content", "()Lcom/jbzd/media/movecartoons/view/page/MyViewPager;", "vp_content", "viewModel$delegate", "getViewModel", "viewModel", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "titleList", "Ljava/util/ArrayList;", "getTitleList", "()Ljava/util/ArrayList;", "setTitleList", "(Ljava/util/ArrayList;)V", "Lcom/jbzd/media/movecartoons/ui/mine/MyVideosFragment;", "mineRecentLongFragment$delegate", "getMineRecentLongFragment", "()Lcom/jbzd/media/movecartoons/ui/mine/MyVideosFragment;", "mineRecentLongFragment", "Lcom/flyco/tablayout/SlidingTabLayout;", "sorting_tab_layout$delegate", "getSorting_tab_layout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "sorting_tab_layout", "Landroidx/fragment/app/Fragment;", "fragmentList", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MyVideosActivity extends MyThemeActivity<MineViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: mineRecentLongFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mineRecentLongFragment = LazyKt__LazyJVMKt.lazy(new Function0<MyVideosFragment>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyVideosActivity$mineRecentLongFragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyVideosFragment invoke() {
            return MyVideosFragment.INSTANCE.newInstance("long");
        }
    });

    @NotNull
    private ArrayList<String> titleList = new ArrayList<>();

    @NotNull
    private ArrayList<Fragment> fragmentList = new ArrayList<>();

    /* renamed from: tv_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyVideosActivity$tv_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final TextView invoke() {
            return (TextView) MyVideosActivity.this.findViewById(R.id.tv_titleRight);
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<MyViewPager>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyVideosActivity$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final MyViewPager invoke() {
            return (MyViewPager) MyVideosActivity.this.findViewById(R.id.vp_content);
        }
    });

    /* renamed from: sorting_tab_layout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sorting_tab_layout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyVideosActivity$sorting_tab_layout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final SlidingTabLayout invoke() {
            return (SlidingTabLayout) MyVideosActivity.this.findViewById(R.id.sorting_tab_layout);
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(MineViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyVideosActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyVideosActivity$special$$inlined$viewModels$default$1
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

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MyVideosActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, MyVideosActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-3$lambda-2, reason: not valid java name */
    public static final void m5862bindEvent$lambda3$lambda2(MyVideosActivity this$0, Boolean bool) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (this$0.getSorting_tab_layout().getCurrentTab() == 0) {
            this$0.getMineRecentLongFragment().getViewModel().getHistoryUpdateSuccess().setValue(bool);
        }
    }

    private final MyVideosFragment getMineRecentLongFragment() {
        return (MyVideosFragment) this.mineRecentLongFragment.getValue();
    }

    private final MineViewModel getViewModel() {
        return (MineViewModel) this.viewModel.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        TextView tv_titleRight = getTv_titleRight();
        Intrinsics.checkNotNullExpressionValue(tv_titleRight, "tv_titleRight");
        BaseThemeActivity.fadeWhenTouch$default(this, tv_titleRight, 0.0f, 1, null);
        this.titleList.add("长视频");
        this.fragmentList.add(getMineRecentLongFragment());
        FragmentManager supportFragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
        ViewPagerAdapter viewPagerAdapter = new ViewPagerAdapter(supportFragmentManager, this.fragmentList, 0, 4, null);
        MyViewPager vp_content = getVp_content();
        vp_content.setScrollble(false);
        vp_content.setOffscreenPageLimit(getTitleList().size());
        vp_content.setAdapter(viewPagerAdapter);
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.mine.MyVideosActivity$bindEvent$1$1
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
        SlidingTabLayout sorting_tab_layout = getSorting_tab_layout();
        MyViewPager vp_content2 = getVp_content();
        Object[] array = getTitleList().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        sorting_tab_layout.m4011e(vp_content2, (String[]) array);
        getViewModel().getHistoryUpdateSuccess().observe(this, new Observer() { // from class: b.a.a.a.t.h.c
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MyVideosActivity.m5862bindEvent$lambda3$lambda2(MyVideosActivity.this, (Boolean) obj);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void clickRight() {
        PostInputActivity.INSTANCE.start(this, 2, "video", "myvideo");
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_myvideos_page;
    }

    public final SlidingTabLayout getSorting_tab_layout() {
        return (SlidingTabLayout) this.sorting_tab_layout.getValue();
    }

    @NotNull
    public final ArrayList<String> getTitleList() {
        return this.titleList;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "我的视频";
    }

    public final TextView getTv_titleRight() {
        return (TextView) this.tv_titleRight.getValue();
    }

    public final MyViewPager getVp_content() {
        return (MyViewPager) this.vp_content.getValue();
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        getMineRecentLongFragment();
    }

    public final void setTitleList(@NotNull ArrayList<String> arrayList) {
        Intrinsics.checkNotNullParameter(arrayList, "<set-?>");
        this.titleList = arrayList;
    }

    @NotNull
    public final MineViewModel viewModelInstance() {
        return getViewModel();
    }
}
