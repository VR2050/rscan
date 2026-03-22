package com.jbzd.media.movecartoons.p396ui.mine.child;

import android.content.Context;
import android.content.Intent;
import android.widget.FrameLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.databinding.ActFollowBinding;
import com.jbzd.media.movecartoons.p396ui.Builder;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import java.util.ArrayList;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\u0011\n\u0002\b\u0007\u0018\u0000 \"2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\"B\u0007¢\u0006\u0004\b!\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\t\u0010\bR-\u0010\u0011\u001a\u0012\u0012\u0004\u0012\u00020\u000b0\nj\b\u0012\u0004\u0012\u00020\u000b`\f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010R\u001d\u0010\u0016\u001a\u00020\u00128B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u000e\u001a\u0004\b\u0014\u0010\u0015R\u001f\u0010\u001b\u001a\u0004\u0018\u00010\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u000e\u001a\u0004\b\u0019\u0010\u001aR#\u0010 \u001a\b\u0012\u0004\u0012\u00020\u00170\u001c8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u000e\u001a\u0004\b\u001e\u0010\u001f¨\u0006#"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/child/FollowActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActFollowBinding;", "", "initView", "()V", "", "showHomeAsUp", "()Z", "contentOverlay", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragments$delegate", "Lkotlin/Lazy;", "getFragments", "()Ljava/util/ArrayList;", "fragments", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "", "type$delegate", "getType", "()Ljava/lang/String;", "type", "", "titleList$delegate", "getTitleList", "()[Ljava/lang/String;", "titleList", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class FollowActivity extends BaseBindingActivity<ActFollowBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_TYPE = "type";

    /* renamed from: type$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy type = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FollowActivity$type$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return FollowActivity.this.getIntent().getStringExtra("type");
        }
    });

    /* renamed from: titleList$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy titleList = LazyKt__LazyJVMKt.lazy(new Function0<String[]>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FollowActivity$titleList$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String[] invoke() {
            return new String[]{"关注", "粉丝"};
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<Fragment>>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FollowActivity$fragments$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<Fragment> invoke() {
            String name = FocusFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name, "FocusFragment::class.java.name");
            String name2 = FansFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name2, "FansFragment::class.java.name");
            return CollectionsKt__CollectionsKt.arrayListOf(new Builder(name).dividerSpace(C4195m.m4785R(0.0f)).build(), new Builder(name2).dividerSpace(C4195m.m4785R(0.0f)).build());
        }
    });

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FollowActivity$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList fragments;
            FragmentManager supportFragmentManager = FollowActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            fragments = FollowActivity.this.getFragments();
            return new ViewPagerAdapter(supportFragmentManager, fragments, 0, 4, null);
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\u0016\u0010\t\u001a\u00020\u00048\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\t\u0010\n¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/child/FollowActivity$Companion;", "", "Landroid/content/Context;", "context", "", "type", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "KEY_TYPE", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull String type) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(type, "type");
            Intent intent = new Intent(context, (Class<?>) FollowActivity.class);
            intent.putExtra("type", type);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<Fragment> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String[] getTitleList() {
        return (String[]) this.titleList.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getType() {
        return (String) this.type.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public boolean contentOverlay() {
        return true;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        C2354n.m2374A(getBodyBinding().btnTitleBack, 0L, new Function1<FrameLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FollowActivity$initView$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FrameLayout frameLayout) {
                invoke2(frameLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull FrameLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                FollowActivity.this.onBackPressed();
            }
        }, 1);
        bodyBinding(new Function1<ActFollowBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FollowActivity$initView$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActFollowBinding actFollowBinding) {
                invoke2(actFollowBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActFollowBinding bodyBinding) {
                ViewPagerAdapter adapter;
                String[] titleList;
                String type;
                String type2;
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                ViewPager viewPager = bodyBinding.vpContent;
                adapter = FollowActivity.this.getAdapter();
                viewPager.setAdapter(adapter);
                SlidingTabLayout slidingTabLayout = bodyBinding.tabLayout;
                ViewPager viewPager2 = bodyBinding.vpContent;
                titleList = FollowActivity.this.getTitleList();
                slidingTabLayout.m4011e(viewPager2, titleList);
                ViewPager viewPager3 = bodyBinding.vpContent;
                type = FollowActivity.this.getType();
                type2 = FollowActivity.this.getType();
                viewPager3.setCurrentItem(!Intrinsics.areEqual(type, type2) ? 1 : 0);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public boolean showHomeAsUp() {
        return false;
    }
}
