package com.jbzd.media.movecartoons.p396ui.index.post;

import android.content.Context;
import android.os.Bundle;
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
import com.jbzd.media.movecartoons.p396ui.post.PostInputActivity;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0086\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 M2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001MB\u0007¢\u0006\u0004\bL\u0010\fJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0017\u0010\t\u001a\u00020\b2\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u000b\u001a\u00020\bH\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\r\u0010\u0005J\u000f\u0010\u000e\u001a\u00020\bH\u0016¢\u0006\u0004\b\u000e\u0010\fJ\u000f\u0010\u000f\u001a\u00020\bH\u0016¢\u0006\u0004\b\u000f\u0010\fJ\u000f\u0010\u0010\u001a\u00020\bH\u0016¢\u0006\u0004\b\u0010\u0010\fR\u001d\u0010\u0016\u001a\u00020\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015R\u0018\u0010\u0018\u001a\u0004\u0018\u00010\u00178\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001e\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0013\u001a\u0004\b\u001c\u0010\u001dR-\u0010%\u001a\u0012\u0012\u0004\u0012\u00020 0\u001fj\b\u0012\u0004\u0012\u00020 `!8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u0013\u001a\u0004\b#\u0010$R#\u0010+\u001a\b\u0012\u0004\u0012\u00020'0&8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u0013\u001a\u0004\b)\u0010*R\u001d\u00100\u001a\u00020,8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0013\u001a\u0004\b.\u0010/R\u001d\u00105\u001a\u0002018F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b2\u0010\u0013\u001a\u0004\b3\u00104R\u001d\u0010:\u001a\u0002068F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u0013\u001a\u0004\b8\u00109R\u0018\u0010<\u001a\u0004\u0018\u00010;8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b<\u0010=R\u001f\u0010B\u001a\u0004\u0018\u00010>8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u0013\u001a\u0004\b@\u0010AR+\u0010F\u001a\u0010\u0012\f\u0012\n C*\u0004\u0018\u00010\u00060\u00060&8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bD\u0010\u0013\u001a\u0004\bE\u0010*R\u001d\u0010K\u001a\u00020G8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bH\u0010\u0013\u001a\u0004\bI\u0010J¨\u0006N"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getDefaultTabPosition", "()I", "", "typePost", "", "showPostTypeDialog", "(Ljava/lang/String;)V", "showPostAiTypeDialog", "()V", "getLayout", "initEvents", "initViews", "onResume", "Landroid/widget/LinearLayout;", "ll_top$delegate", "Lkotlin/Lazy;", "getLl_top", "()Landroid/widget/LinearLayout;", "ll_top", "Lcom/jbzd/media/movecartoons/view/PostTypeDialog;", "mChoicesDialog", "Lcom/jbzd/media/movecartoons/view/PostTypeDialog;", "Landroid/widget/TextView;", "itv_search$delegate", "getItv_search", "()Landroid/widget/TextView;", "itv_search", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "Lkotlin/collections/ArrayList;", "tabEntityBeans$delegate", "getTabEntityBeans", "()Ljava/util/ArrayList;", "tabEntityBeans", "", "Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment;", "fragments$delegate", "getFragments", "()Ljava/util/List;", "fragments", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "Landroid/widget/ImageView;", "img_community_post$delegate", "getImg_community_post", "()Landroid/widget/ImageView;", "img_community_post", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "mPostAiTypeDialog", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "mBottomTab$delegate", "getMBottomTab", "()Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "mBottomTab", "kotlin.jvm.PlatformType", "tabEntities$delegate", "getTabEntities", "tabEntities", "Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout$delegate", "getTabLayout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostHomeFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_BG = "bg";

    @NotNull
    public static final String KEY_BOTTOM_TAB = "bottom_tab";

    @NotNull
    public static final String KEY_INDICATOR = "indicator";

    @Nullable
    private PostTypeDialog mChoicesDialog;

    @Nullable
    private PostAiTypeDialog mPostAiTypeDialog;

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends CommunityTabSingleFragment>>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$fragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends CommunityTabSingleFragment> invoke() {
            ArrayList tabEntityBeans;
            tabEntityBeans = PostHomeFragment.this.getTabEntityBeans();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntityBeans, 10));
            Iterator it = tabEntityBeans.iterator();
            while (it.hasNext()) {
                arrayList.add(CommunityTabSingleFragment.INSTANCE.newInstance((MainMenusBean) it.next(), "normal"));
            }
            return arrayList;
        }
    });

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            List fragments;
            FragmentManager childFragmentManager = PostHomeFragment.this.getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
            fragments = PostHomeFragment.this.getFragments();
            return new ViewPagerAdapter(childFragmentManager, (ArrayList) fragments, 0, 4, null);
        }
    });

    /* renamed from: mBottomTab$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mBottomTab = LazyKt__LazyJVMKt.lazy(new Function0<BottomTab>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$mBottomTab$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final BottomTab invoke() {
            Bundle arguments = PostHomeFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return (BottomTab) arguments.getParcelable("bottom_tab");
        }
    });

    /* renamed from: tabEntityBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntityBeans = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MainMenusBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$tabEntityBeans$2
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
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends String>>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$tabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends String> invoke() {
            ArrayList tabEntityBeans;
            tabEntityBeans = PostHomeFragment.this.getTabEntityBeans();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntityBeans, 10));
            Iterator it = tabEntityBeans.iterator();
            while (it.hasNext()) {
                arrayList.add(((MainMenusBean) it.next()).name);
            }
            return arrayList;
        }
    });

    /* renamed from: ll_top$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_top = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$ll_top$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = PostHomeFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_top);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: itv_search$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_search = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$itv_search$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = PostHomeFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.itv_search);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            View view = PostHomeFragment.this.getView();
            ViewPager viewPager = view == null ? null : (ViewPager) view.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tabLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$tabLayout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            View view = PostHomeFragment.this.getView();
            SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    /* renamed from: img_community_post$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy img_community_post = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$img_community_post$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = PostHomeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.img_community_post);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\f\u0010\rJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\b\u001a\u00020\u00078\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\b\u0010\tR\u0016\u0010\n\u001a\u00020\u00078\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\n\u0010\tR\u0016\u0010\u000b\u001a\u00020\u00078\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000b\u0010\t¨\u0006\u000e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "bottomTab", "Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/ui/index/BottomTab;)Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeFragment;", "", "KEY_BG", "Ljava/lang/String;", "KEY_BOTTOM_TAB", "KEY_INDICATOR", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final PostHomeFragment newInstance(@NotNull BottomTab bottomTab) {
            Intrinsics.checkNotNullParameter(bottomTab, "bottomTab");
            PostHomeFragment postHomeFragment = new PostHomeFragment();
            Bundle bundle = new Bundle();
            bundle.putParcelable("bottom_tab", bottomTab);
            Unit unit = Unit.INSTANCE;
            postHomeFragment.setArguments(bundle);
            return postHomeFragment;
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
    public final List<CommunityTabSingleFragment> getFragments() {
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

    private final void showPostTypeDialog(String typePost) {
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
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        getLl_top().setPadding(0, ImmersionBar.getStatusBarHeight(this) + 30, 0, 0);
        C2354n.m2374A(getItv_search(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$initViews$2
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
                Context requireContext = PostHomeFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, "post");
            }
        }, 1);
        ViewPager vp_content = getVp_content();
        vp_content.setOffscreenPageLimit(getTabEntities().size());
        vp_content.setAdapter(getAdapter());
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$initViews$3$1
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
        SlidingTabLayout tabLayout = getTabLayout();
        ViewPager vp_content2 = getVp_content();
        Object[] array = getTabEntities().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tabLayout.m4011e(vp_content2, (String[]) array);
        if (!getTabEntities().isEmpty()) {
            getVp_content().setCurrentItem(getDefaultTabPosition());
        }
        MyThemeFragment.fadeWhenTouch$default(this, getImg_community_post(), 0.0f, 1, null);
        C2354n.m2374A(getImg_community_post(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeFragment$initViews$5
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
                tabEntityBeans = PostHomeFragment.this.getTabEntityBeans();
                if (Intrinsics.areEqual(((MainMenusBean) tabEntityBeans.get(PostHomeFragment.this.getTabLayout().getCurrentTab())).is_ai, "y")) {
                    PostHomeFragment.this.showPostAiTypeDialog();
                    return;
                }
                PostInputActivity.Companion companion = PostInputActivity.INSTANCE;
                Context requireContext = PostHomeFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, 3, "homepage", "post");
            }
        }, 1);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
    }
}
