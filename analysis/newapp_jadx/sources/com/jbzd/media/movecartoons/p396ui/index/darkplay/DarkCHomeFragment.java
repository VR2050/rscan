package com.jbzd.media.movecartoons.p396ui.index.darkplay;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.BottomTab;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.SearchHomeActivity;
import com.jbzd.media.movecartoons.view.PostAiTypeDialog;
import com.jbzd.media.movecartoons.view.PostTypeDialog;
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
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u008a\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u0000 N2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001NB\u0007¢\u0006\u0004\bM\u0010\fJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0017\u0010\t\u001a\u00020\b2\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u000b\u001a\u00020\bH\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\r\u0010\u0005J\u000f\u0010\u000e\u001a\u00020\bH\u0016¢\u0006\u0004\b\u000e\u0010\fJ\u000f\u0010\u000f\u001a\u00020\bH\u0016¢\u0006\u0004\b\u000f\u0010\fJ\u0017\u0010\u0011\u001a\u00020\b2\b\u0010\u0010\u001a\u0004\u0018\u00010\u0006¢\u0006\u0004\b\u0011\u0010\nR\u001d\u0010\u0017\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001c\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u0014\u001a\u0004\b\u001a\u0010\u001bR\u001d\u0010!\u001a\u00020\u001d8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u0014\u001a\u0004\b\u001f\u0010 R\u0018\u0010#\u001a\u0004\u0018\u00010\"8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b#\u0010$R+\u0010*\u001a\u0010\u0012\f\u0012\n &*\u0004\u0018\u00010\u00060\u00060%8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u0014\u001a\u0004\b(\u0010)R-\u00101\u001a\u0012\u0012\u0004\u0012\u00020,0+j\b\u0012\u0004\u0012\u00020,`-8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u0014\u001a\u0004\b/\u00100R\u001d\u00106\u001a\u0002028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b3\u0010\u0014\u001a\u0004\b4\u00105R\u0018\u00108\u001a\u0004\u0018\u0001078\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b8\u00109R\u001d\u0010>\u001a\u00020:8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b;\u0010\u0014\u001a\u0004\b<\u0010=R\u001d\u0010C\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b@\u0010\u0014\u001a\u0004\bA\u0010BR\u001f\u0010H\u001a\u0004\u0018\u00010D8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u0014\u001a\u0004\bF\u0010GR#\u0010L\u001a\b\u0012\u0004\u0012\u00020I0%8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bJ\u0010\u0014\u001a\u0004\bK\u0010)¨\u0006O"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkCHomeFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getDefaultTabPosition", "()I", "", "typePost", "", "showPostTypeDialog", "(Ljava/lang/String;)V", "showPostAiTypeDialog", "()V", "getLayout", "initEvents", "initViews", "tabId", "showTab", "Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout$delegate", "Lkotlin/Lazy;", "getTabLayout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout", "Landroid/widget/LinearLayout;", "ll_top$delegate", "getLl_top", "()Landroid/widget/LinearLayout;", "ll_top", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "Lcom/jbzd/media/movecartoons/view/PostTypeDialog;", "mChoicesDialog", "Lcom/jbzd/media/movecartoons/view/PostTypeDialog;", "", "kotlin.jvm.PlatformType", "tabEntities$delegate", "getTabEntities", "()Ljava/util/List;", "tabEntities", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "Lkotlin/collections/ArrayList;", "tabEntityBeans$delegate", "getTabEntityBeans", "()Ljava/util/ArrayList;", "tabEntityBeans", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "mPostAiTypeDialog", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "Landroid/widget/ImageView;", "img_community_post$delegate", "getImg_community_post", "()Landroid/widget/ImageView;", "img_community_post", "Landroid/widget/TextView;", "itv_search$delegate", "getItv_search", "()Landroid/widget/TextView;", "itv_search", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "mBottomTab$delegate", "getMBottomTab", "()Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "mBottomTab", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment;", "fragments$delegate", "getFragments", "fragments", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DarkCHomeFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_BG = "bg";

    @NotNull
    public static final String KEY_BOTTOM_TAB = "bottom_tab";

    @Nullable
    private PostTypeDialog mChoicesDialog;

    @Nullable
    private PostAiTypeDialog mPostAiTypeDialog;

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            List fragments;
            FragmentManager childFragmentManager = DarkCHomeFragment.this.getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
            fragments = DarkCHomeFragment.this.getFragments();
            return new ViewPagerAdapter(childFragmentManager, (ArrayList) fragments, 0, 4, null);
        }
    });

    /* renamed from: mBottomTab$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mBottomTab = LazyKt__LazyJVMKt.lazy(new Function0<BottomTab>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$mBottomTab$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final BottomTab invoke() {
            Bundle arguments = DarkCHomeFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return (BottomTab) arguments.getParcelable("bottom_tab");
        }
    });

    /* renamed from: tabEntityBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntityBeans = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MainMenusBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$tabEntityBeans$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<MainMenusBean> invoke() {
            ArrayList<MainMenusBean> arrayList = new ArrayList<>();
            MyApp myApp = MyApp.f9891f;
            List<MainMenusBean> list = MyApp.m4185f().post_nav;
            if (C2354n.m2414N0(list)) {
                arrayList.addAll(list);
            }
            return arrayList;
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends String>>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$tabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends String> invoke() {
            ArrayList tabEntityBeans;
            tabEntityBeans = DarkCHomeFragment.this.getTabEntityBeans();
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
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends DarkTabSingleFragment>>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$fragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends DarkTabSingleFragment> invoke() {
            ArrayList tabEntityBeans;
            tabEntityBeans = DarkCHomeFragment.this.getTabEntityBeans();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntityBeans, 10));
            Iterator it = tabEntityBeans.iterator();
            while (it.hasNext()) {
                arrayList.add(DarkTabSingleFragment.INSTANCE.newInstance((MainMenusBean) it.next(), "dark"));
            }
            return arrayList;
        }
    });

    /* renamed from: ll_top$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_top = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$ll_top$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = DarkCHomeFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_top);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: itv_search$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_search = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$itv_search$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = DarkCHomeFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.itv_search);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            View view = DarkCHomeFragment.this.getView();
            ViewPager viewPager = view == null ? null : (ViewPager) view.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tabLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$tabLayout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            View view = DarkCHomeFragment.this.getView();
            SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    /* renamed from: img_community_post$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy img_community_post = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$img_community_post$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = DarkCHomeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.img_community_post);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\b\u001a\u00020\u00078\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\b\u0010\tR\u0016\u0010\n\u001a\u00020\u00078\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\n\u0010\t¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkCHomeFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "bottomTab", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkCHomeFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/ui/index/BottomTab;)Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkCHomeFragment;", "", "KEY_BG", "Ljava/lang/String;", "KEY_BOTTOM_TAB", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final DarkCHomeFragment newInstance(@NotNull BottomTab bottomTab) {
            Intrinsics.checkNotNullParameter(bottomTab, "bottomTab");
            DarkCHomeFragment darkCHomeFragment = new DarkCHomeFragment();
            Bundle bundle = new Bundle();
            bundle.putParcelable("bottom_tab", bottomTab);
            Unit unit = Unit.INSTANCE;
            darkCHomeFragment.setArguments(bundle);
            return darkCHomeFragment;
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
        return 1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<DarkTabSingleFragment> getFragments() {
        return (List) this.fragments.getValue();
    }

    private final BottomTab getMBottomTab() {
        return (BottomTab) this.mBottomTab.getValue();
    }

    private final List<String> getTabEntities() {
        return (List) this.tabEntities.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<MainMenusBean> getTabEntityBeans() {
        return (ArrayList) this.tabEntityBeans.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showPostAiTypeDialog() {
        PostAiTypeDialog postAiTypeDialog;
        if (this.mPostAiTypeDialog == null) {
            PostAiTypeDialog.Companion companion = PostAiTypeDialog.INSTANCE;
            FragmentActivity requireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
            this.mPostAiTypeDialog = companion.showPostTypeDialog(requireActivity, this);
        }
        PostAiTypeDialog postAiTypeDialog2 = this.mPostAiTypeDialog;
        Intrinsics.checkNotNull(postAiTypeDialog2);
        postAiTypeDialog2.setFragment(this);
        PostAiTypeDialog postAiTypeDialog3 = this.mPostAiTypeDialog;
        if (postAiTypeDialog3 != null) {
            if (!Intrinsics.areEqual(postAiTypeDialog3 == null ? null : Boolean.valueOf(postAiTypeDialog3.isShowing()), Boolean.FALSE) || (postAiTypeDialog = this.mPostAiTypeDialog) == null) {
                return;
            }
            postAiTypeDialog.show();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showPostTypeDialog(String typePost) {
        PostTypeDialog postTypeDialog;
        if (this.mChoicesDialog == null) {
            PostTypeDialog.Companion companion = PostTypeDialog.INSTANCE;
            FragmentActivity requireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
            this.mChoicesDialog = companion.showPostTypeDialog(requireActivity, this);
        }
        PostTypeDialog postTypeDialog2 = this.mChoicesDialog;
        Intrinsics.checkNotNull(postTypeDialog2);
        postTypeDialog2.setFragment(this);
        PostTypeDialog postTypeDialog3 = this.mChoicesDialog;
        Intrinsics.checkNotNull(postTypeDialog3);
        postTypeDialog3.setPostType(typePost);
        PostTypeDialog postTypeDialog4 = this.mChoicesDialog;
        if (postTypeDialog4 != null) {
            if (!Intrinsics.areEqual(postTypeDialog4 == null ? null : Boolean.valueOf(postTypeDialog4.isShowing()), Boolean.FALSE) || (postTypeDialog = this.mChoicesDialog) == null) {
                return;
            }
            postTypeDialog.show();
        }
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final ImageView getImg_community_post() {
        return (ImageView) this.img_community_post.getValue();
    }

    @NotNull
    public final TextView getItv_search() {
        return (TextView) this.itv_search.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_community;
    }

    @NotNull
    public final LinearLayout getLl_top() {
        return (LinearLayout) this.ll_top.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTabLayout() {
        return (SlidingTabLayout) this.tabLayout.getValue();
    }

    @NotNull
    public final ViewPager getVp_content() {
        return (ViewPager) this.vp_content.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        super.initEvents();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getLl_top().setPadding(0, ImmersionBar.getStatusBarHeight(this), 0, 0);
        C2354n.m2374A(getItv_search(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$initViews$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SearchHomeActivity.Companion companion = SearchHomeActivity.INSTANCE;
                Context requireContext = DarkCHomeFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, "dark");
            }
        }, 1);
        ViewPager vp_content = getVp_content();
        vp_content.setOffscreenPageLimit(getTabEntities().size());
        vp_content.setAdapter(getAdapter());
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$initViews$2$1
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
        getArguments();
        SlidingTabLayout tabLayout = getTabLayout();
        ViewPager vp_content2 = getVp_content();
        Object[] array = getTabEntities().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tabLayout.m4011e(vp_content2, (String[]) array);
        if (!getTabEntities().isEmpty()) {
            getVp_content().setCurrentItem(getDefaultTabPosition());
        }
        C2354n.m2374A(getImg_community_post(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkCHomeFragment$initViews$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                ArrayList tabEntityBeans;
                Intrinsics.checkNotNullParameter(it, "it");
                tabEntityBeans = DarkCHomeFragment.this.getTabEntityBeans();
                if (Intrinsics.areEqual(((MainMenusBean) tabEntityBeans.get(DarkCHomeFragment.this.getTabLayout().getCurrentTab())).is_ai, "y")) {
                    DarkCHomeFragment.this.showPostAiTypeDialog();
                } else {
                    DarkCHomeFragment.this.showPostTypeDialog("homepage");
                }
            }
        }, 1);
    }

    public final void showTab(@Nullable String tabId) {
        Iterator<MainMenusBean> it = getTabEntityBeans().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().f10030id, tabId)) {
                getVp_content().setCurrentItem(i2);
                return;
            }
            i2 = i3;
        }
    }
}
