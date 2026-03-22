package com.jbzd.media.movecartoons.p396ui.mine.cache;

import android.content.Context;
import androidx.activity.ComponentActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.SubmitDialog;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.mine.MineCacheLongFragment;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.p396ui.mine.cache.CacheActivity;
import com.jbzd.media.movecartoons.view.page.MyViewPager;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
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
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\f\u0018\u0000  2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001 B\u0007¢\u0006\u0004\b\u001f\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\tH\u0016¢\u0006\u0004\b\f\u0010\u000bJ\u000f\u0010\r\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\r\u0010\u0005J\u000f\u0010\u000e\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000e\u0010\u000fR&\u0010\u0013\u001a\u0012\u0012\u0004\u0012\u00020\u00110\u0010j\b\u0012\u0004\u0012\u00020\u0011`\u00128\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0013\u0010\u0014R\u001d\u0010\u001a\u001a\u00020\u00158B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0017\u001a\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001d\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0017\u001a\u0004\b\u001c\u0010\u000fR&\u0010\u001e\u001a\u0012\u0012\u0004\u0012\u00020\t0\u0010j\b\u0012\u0004\u0012\u00020\t`\u00128\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001e\u0010\u0014¨\u0006!"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/cache/CacheActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "", "bindEvent", "()V", "", "getLayoutId", "()I", "", "getTopBarTitle", "()Ljava/lang/String;", "getRightTitle", "clickRight", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragmentList", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/ui/mine/MineCacheLongFragment;", "mineCacheLongFragment$delegate", "Lkotlin/Lazy;", "getMineCacheLongFragment", "()Lcom/jbzd/media/movecartoons/ui/mine/MineCacheLongFragment;", "mineCacheLongFragment", "viewModel$delegate", "getViewModel", "viewModel", "titleList", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CacheActivity extends MyThemeViewModelActivity<MineViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private ArrayList<Fragment> fragmentList;

    /* renamed from: mineCacheLongFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mineCacheLongFragment = LazyKt__LazyJVMKt.lazy(new Function0<MineCacheLongFragment>() { // from class: com.jbzd.media.movecartoons.ui.mine.cache.CacheActivity$mineCacheLongFragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MineCacheLongFragment invoke() {
            return MineCacheLongFragment.INSTANCE.newInstance("long");
        }
    });

    @NotNull
    private ArrayList<String> titleList;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/cache/CacheActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, CacheActivity.class);
        }
    }

    public CacheActivity() {
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("长视频");
        Unit unit = Unit.INSTANCE;
        this.titleList = arrayList;
        this.fragmentList = new ArrayList<>();
        this.viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(MineViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.mine.cache.CacheActivity$special$$inlined$viewModels$default$2
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
        }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.mine.cache.CacheActivity$special$$inlined$viewModels$default$1
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
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-4$lambda-3, reason: not valid java name */
    public static final void m5863bindEvent$lambda4$lambda3(CacheActivity this$0, Boolean bool) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (((SlidingTabLayout) this$0.findViewById(R$id.sorting_tab_layout)).getCurrentTab() == 0) {
            this$0.getMineCacheLongFragment().getViewModel().getHistoryUpdateSuccess().setValue(bool);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MineCacheLongFragment getMineCacheLongFragment() {
        return (MineCacheLongFragment) this.mineCacheLongFragment.getValue();
    }

    private final MineViewModel getViewModel() {
        return (MineViewModel) this.viewModel.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        this.fragmentList.add(getMineCacheLongFragment());
        FragmentManager supportFragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
        ViewPagerAdapter viewPagerAdapter = new ViewPagerAdapter(supportFragmentManager, this.fragmentList, 0, 4, null);
        int i2 = R$id.vp_content;
        MyViewPager myViewPager = (MyViewPager) findViewById(i2);
        myViewPager.setScrollble(false);
        myViewPager.setOffscreenPageLimit(this.titleList.size());
        myViewPager.setAdapter(viewPagerAdapter);
        myViewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.mine.cache.CacheActivity$bindEvent$1$1
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
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) findViewById(R$id.sorting_tab_layout);
        MyViewPager myViewPager2 = (MyViewPager) findViewById(i2);
        Object[] array = this.titleList.toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e(myViewPager2, (String[]) array);
        getViewModel().getHistoryUpdateSuccess().observe(this, new Observer() { // from class: b.a.a.a.t.h.d.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                CacheActivity.m5863bindEvent$lambda4$lambda3(CacheActivity.this, (Boolean) obj);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void clickRight() {
        if (((SlidingTabLayout) findViewById(R$id.sorting_tab_layout)).getCurrentTab() == 0 && getMineCacheLongFragment().getMFragment().getAdapter().getData().size() == 0) {
            C2354n.m2451Z1("请先缓存长视频");
        } else {
            new SubmitDialog(new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.cache.CacheActivity$clickRight$1
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
                    MineCacheLongFragment mineCacheLongFragment;
                    if (((SlidingTabLayout) CacheActivity.this.findViewById(R$id.sorting_tab_layout)).getCurrentTab() == 0) {
                        mineCacheLongFragment = CacheActivity.this.getMineCacheLongFragment();
                        mineCacheLongFragment.getViewModel().getCacheAllData().setValue(Boolean.TRUE);
                    }
                }
            }).show(getSupportFragmentManager(), "SubmitDialog");
        }
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_history_page;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getRightTitle() {
        return "";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "缓存视频";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public MineViewModel viewModelInstance() {
        return getViewModel();
    }
}
