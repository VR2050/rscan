package com.jbzd.media.movecartoons.p396ui.index.home;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.exifinterface.media.ExifInterface;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.OrderByPopup;
import com.jbzd.media.movecartoons.p396ui.dialog.TagsDialog;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeListFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.OrdinaryFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.model.TopViewModel;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0835a0;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u009d\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010 \n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0011*\u0001@\u0018\u0000 ^2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001^B\u0007¢\u0006\u0004\b]\u0010\rJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\f\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\u000e\u0010\rJ\u000f\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\u000bH\u0017¢\u0006\u0004\b\u0012\u0010\rJ\u000f\u0010\u0013\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0013\u0010\u0014R\u001e\u0010\u0016\u001a\n\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u00158\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0016\u0010\u0017R\u001d\u0010\u001d\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\u001f\u0010\"\u001a\u0004\u0018\u00010\u001e8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u001a\u001a\u0004\b \u0010!R\u001d\u0010'\u001a\u00020#8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u001a\u001a\u0004\b%\u0010&R\u0018\u0010)\u001a\u0004\u0018\u00010(8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b)\u0010*R\u0018\u0010,\u001a\u0004\u0018\u00010+8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b,\u0010-R\u001d\u00100\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u001a\u001a\u0004\b/\u0010\u0014R\u001d\u00105\u001a\u0002018B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b2\u0010\u001a\u001a\u0004\b3\u00104R\u001d\u0010:\u001a\u0002068F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u001a\u001a\u0004\b8\u00109R\u001d\u0010?\u001a\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b<\u0010\u001a\u001a\u0004\b=\u0010>R\u0016\u0010A\u001a\u00020@8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bA\u0010BR\u001d\u0010G\u001a\u00020C8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bD\u0010\u001a\u001a\u0004\bE\u0010FR-\u0010M\u001a\u0012\u0012\u0004\u0012\u00020\u00030Hj\b\u0012\u0004\u0012\u00020\u0003`I8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bJ\u0010\u001a\u001a\u0004\bK\u0010LR\u001d\u0010R\u001a\u00020N8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bO\u0010\u001a\u001a\u0004\bP\u0010QR\u001d\u0010U\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bS\u0010\u001a\u001a\u0004\bT\u0010\u001cR\u001d\u0010X\u001a\u00020C8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bV\u0010\u001a\u001a\u0004\bW\u0010FR\u001f\u0010\\\u001a\u0004\u0018\u00010\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bY\u0010\u001a\u001a\u0004\bZ\u0010[¨\u0006_"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/OrdinaryFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/index/home/model/TopViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "tag", "", "contain", "(Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;)Z", "", "getSelectedTagIds", "()Ljava/lang/String;", "", "showTagChooseDialog", "()V", "showTagsList", "", "getLayout", "()I", "initViews", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/index/home/model/TopViewModel;", "", "mAllTags", "Ljava/util/List;", "Landroid/widget/RelativeLayout;", "rl_tagLayoutClick$delegate", "Lkotlin/Lazy;", "getRl_tagLayoutClick", "()Landroid/widget/RelativeLayout;", "rl_tagLayoutClick", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;", "flavorSwipeLayout$delegate", "getFlavorSwipeLayout", "()Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;", "flavorSwipeLayout", "Lb/a/a/a/a/a0;", "curOrderBy", "Lb/a/a/a/a/a0;", "Lcom/jbzd/media/movecartoons/ui/dialog/OrderByPopup;", "popup", "Lcom/jbzd/media/movecartoons/ui/dialog/OrderByPopup;", "viewModel$delegate", "getViewModel", "viewModel", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment;", "mFragment$delegate", "getMFragment", "()Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment;", "mFragment", "Lcom/google/android/material/appbar/AppBarLayout;", "app_bar_layout$delegate", "getApp_bar_layout", "()Lcom/google/android/material/appbar/AppBarLayout;", "app_bar_layout", "Landroidx/recyclerview/widget/RecyclerView;", "rv_flavor$delegate", "getRv_flavor", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_flavor", "com/jbzd/media/movecartoons/ui/index/home/OrdinaryFragment$mTagAdapter$1", "mTagAdapter", "Lcom/jbzd/media/movecartoons/ui/index/home/OrdinaryFragment$mTagAdapter$1;", "Landroid/widget/LinearLayout;", "ll_tag$delegate", "getLl_tag", "()Landroid/widget/LinearLayout;", "ll_tag", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "mSelectedTags$delegate", "getMSelectedTags", "()Ljava/util/ArrayList;", "mSelectedTags", "Landroid/widget/TextView;", "tv_orderByName$delegate", "getTv_orderByName", "()Landroid/widget/TextView;", "tv_orderByName", "rl_parent$delegate", "getRl_parent", "rl_parent", "ll_orderBy$delegate", "getLl_orderBy", "ll_orderBy", "mIndex$delegate", "getMIndex", "()Ljava/lang/Integer;", "mIndex", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class OrdinaryFragment extends MyThemeViewModelFragment<TopViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_BG = "bg";

    @NotNull
    private static final String KEY_INDEX = "index";

    @NotNull
    private static final String KEY_TAB = "tab_bean";

    @Nullable
    private C0835a0 curOrderBy;

    @Nullable
    private List<? extends TagBean> mAllTags;

    @Nullable
    private OrderByPopup popup;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    /* renamed from: mIndex$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mIndex = LazyKt__LazyJVMKt.lazy(new Function0<Integer>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$mIndex$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final Integer invoke() {
            Bundle arguments = OrdinaryFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return Integer.valueOf(arguments.getInt("index"));
        }
    });

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = OrdinaryFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable("tab_bean"));
        }
    });

    /* renamed from: mFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFragment = LazyKt__LazyJVMKt.lazy(new Function0<HomeListFragment>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$mFragment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HomeListFragment invoke() {
            MainMenusBean mTabBean;
            Integer mIndex;
            HomeListFragment.Companion companion = HomeListFragment.INSTANCE;
            mTabBean = OrdinaryFragment.this.getMTabBean();
            mIndex = OrdinaryFragment.this.getMIndex();
            Intrinsics.checkNotNull(mIndex);
            return HomeListFragment.Companion.newInstance$default(companion, mTabBean, "", false, null, mIndex.intValue(), 8, null);
        }
    });

    /* renamed from: mSelectedTags$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mSelectedTags = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<TagBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$mSelectedTags$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<TagBean> invoke() {
            ArrayList<TagBean> arrayList = new ArrayList<>();
            OrdinaryFragment.this.getMTabBean();
            return arrayList;
        }
    });

    @NotNull
    private final OrdinaryFragment$mTagAdapter$1 mTagAdapter = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$mTagAdapter$1
        {
            super(R.layout.item_home_tag, null, 2, null);
        }

        @Override // com.chad.library.adapter.base.BaseQuickAdapter
        public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
            boolean contain;
            boolean contain2;
            boolean contain3;
            Intrinsics.checkNotNullParameter(helper, "helper");
            Intrinsics.checkNotNullParameter(item, "item");
            OrdinaryFragment ordinaryFragment = OrdinaryFragment.this;
            String str = item.name;
            if (str == null) {
                str = "";
            }
            helper.m3919i(R.id.tv_name, Intrinsics.stringPlus(ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, str));
            TextView textView = (TextView) helper.m3912b(R.id.tv_name);
            contain = ordinaryFragment.contain(item);
            textView.setSelected(contain);
            LinearLayout linearLayout = (LinearLayout) helper.m3912b(R.id.ll_parent);
            contain2 = ordinaryFragment.contain(item);
            linearLayout.setSelected(contain2);
            ImageView imageView = (ImageView) helper.m3912b(R.id.iv_del);
            contain3 = ordinaryFragment.contain(item);
            imageView.setVisibility(contain3 ? 0 : 8);
        }
    };

    /* renamed from: ll_tag$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_tag = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$ll_tag$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = OrdinaryFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_tag);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: rv_flavor$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_flavor = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$rv_flavor$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            View view = OrdinaryFragment.this.getView();
            RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_flavor);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: app_bar_layout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy app_bar_layout = LazyKt__LazyJVMKt.lazy(new Function0<AppBarLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$app_bar_layout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppBarLayout invoke() {
            View view = OrdinaryFragment.this.getView();
            AppBarLayout appBarLayout = view == null ? null : (AppBarLayout) view.findViewById(R.id.app_bar_layout);
            Intrinsics.checkNotNull(appBarLayout);
            return appBarLayout;
        }
    });

    /* renamed from: flavorSwipeLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy flavorSwipeLayout = LazyKt__LazyJVMKt.lazy(new Function0<SwipeRefreshLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$flavorSwipeLayout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SwipeRefreshLayout invoke() {
            View view = OrdinaryFragment.this.getView();
            SwipeRefreshLayout swipeRefreshLayout = view == null ? null : (SwipeRefreshLayout) view.findViewById(R.id.flavorSwipeLayout);
            Intrinsics.checkNotNull(swipeRefreshLayout);
            return swipeRefreshLayout;
        }
    });

    /* renamed from: rl_tagLayoutClick$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rl_tagLayoutClick = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$rl_tagLayoutClick$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            View view = OrdinaryFragment.this.getView();
            RelativeLayout relativeLayout = view == null ? null : (RelativeLayout) view.findViewById(R.id.rl_tagLayoutClick);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: tv_orderByName$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_orderByName = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$tv_orderByName$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = OrdinaryFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_orderByName);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: ll_orderBy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_orderBy = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$ll_orderBy$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = OrdinaryFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_orderBy);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: rl_parent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rl_parent = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$rl_parent$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            View view = OrdinaryFragment.this.getView();
            RelativeLayout relativeLayout = view == null ? null : (RelativeLayout) view.findViewById(R.id.rl_parent);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J'\u0010\b\u001a\u00020\u00072\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u0004¢\u0006\u0004\b\b\u0010\tR\u0016\u0010\u000b\u001a\u00020\n8\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u000b\u0010\fR\u0016\u0010\r\u001a\u00020\n8\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\r\u0010\fR\u0016\u0010\u000e\u001a\u00020\n8\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u000e\u0010\f¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/OrdinaryFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "", OrdinaryFragment.KEY_INDEX, "bg", "Lcom/jbzd/media/movecartoons/ui/index/home/OrdinaryFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;II)Lcom/jbzd/media/movecartoons/ui/index/home/OrdinaryFragment;", "", "KEY_BG", "Ljava/lang/String;", "KEY_INDEX", "KEY_TAB", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final OrdinaryFragment newInstance(@Nullable MainMenusBean tabBean, int index, int bg) {
            OrdinaryFragment ordinaryFragment = new OrdinaryFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("tab_bean", tabBean);
            bundle.putInt(OrdinaryFragment.KEY_INDEX, index);
            bundle.putInt("bg", bg);
            Unit unit = Unit.INSTANCE;
            ordinaryFragment.setArguments(bundle);
            return ordinaryFragment;
        }
    }

    /* JADX WARN: Type inference failed for: r0v8, types: [com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$mTagAdapter$1] */
    public OrdinaryFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$special$$inlined$viewModels$default$1
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
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(TopViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$special$$inlined$viewModels$default$2
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
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean contain(TagBean tag) {
        Iterator<TagBean> it = getMSelectedTags().iterator();
        while (it.hasNext()) {
            if (TextUtils.equals(it.next().f10032id, tag.f10032id)) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final HomeListFragment getMFragment() {
        return (HomeListFragment) this.mFragment.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Integer getMIndex() {
        return (Integer) this.mIndex.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<TagBean> getMSelectedTags() {
        return (ArrayList) this.mSelectedTags.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MainMenusBean getMTabBean() {
        return (MainMenusBean) this.mTabBean.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getSelectedTagIds() {
        return CollectionsKt___CollectionsKt.joinToString$default(getMSelectedTags(), ChineseToPinyinResource.Field.COMMA, null, null, 0, null, new Function1<TagBean, CharSequence>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$getSelectedTagIds$1
            @Override // kotlin.jvm.functions.Function1
            @NotNull
            public final CharSequence invoke(@NotNull TagBean it) {
                Intrinsics.checkNotNullParameter(it, "it");
                String str = it.f10032id;
                Intrinsics.checkNotNullExpressionValue(str, "it.id");
                return str;
            }
        }, 30, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5833initViews$lambda2$lambda1(OrdinaryFragment this$0, List list) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.mAllTags = list;
        this$0.showTagsList();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-3, reason: not valid java name */
    public static final void m5834initViews$lambda3(OrdinaryFragment this$0, AppBarLayout appBarLayout, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getFlavorSwipeLayout().setEnabled(i2 == 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5835initViews$lambda5$lambda4(OrdinaryFragment this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        TopViewModel.loadInfo$default(this$0.getViewModel(), false, 1, null);
        this$0.getMFragment().refresh();
        this$0.getFlavorSwipeLayout().setRefreshing(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showTagChooseDialog() {
        List<TagBean> value = getViewModel().getTags().getValue();
        if (value == null || value.isEmpty()) {
            getViewModel().loadInfo(true);
        } else {
            new TagsDialog(value, getMSelectedTags(), new Function1<List<? extends TagBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$showTagChooseDialog$1
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(List<? extends TagBean> list) {
                    invoke2(list);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull List<? extends TagBean> it) {
                    ArrayList mSelectedTags;
                    HomeListFragment mFragment;
                    String selectedTagIds;
                    String selectedTagIds2;
                    ArrayList mSelectedTags2;
                    Intrinsics.checkNotNullParameter(it, "it");
                    mSelectedTags = OrdinaryFragment.this.getMSelectedTags();
                    mSelectedTags.clear();
                    if (!it.isEmpty()) {
                        mSelectedTags2 = OrdinaryFragment.this.getMSelectedTags();
                        mSelectedTags2.addAll(it);
                    }
                    OrdinaryFragment.this.showTagsList();
                    mFragment = OrdinaryFragment.this.getMFragment();
                    selectedTagIds = OrdinaryFragment.this.getSelectedTagIds();
                    mFragment.updateTags(selectedTagIds);
                    TopViewModel viewModel = OrdinaryFragment.this.getViewModel();
                    selectedTagIds2 = OrdinaryFragment.this.getSelectedTagIds();
                    viewModel.updateUserSelectedTags(selectedTagIds2);
                }
            }).show(getChildFragmentManager(), "TagsDialog");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showTagsList() {
        ArrayList arrayList = new ArrayList();
        List<? extends TagBean> list = this.mAllTags;
        if (getMSelectedTags().size() != 0) {
            arrayList.addAll(getMSelectedTags());
        } else if (list != null) {
            if (list.size() > 8) {
                arrayList.addAll(list.subList(0, 8));
            } else {
                arrayList.addAll(list);
            }
        }
        setNewData(arrayList);
        getRl_parent().setVisibility(arrayList.size() == 0 ? 8 : 0);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final AppBarLayout getApp_bar_layout() {
        return (AppBarLayout) this.app_bar_layout.getValue();
    }

    @NotNull
    public final SwipeRefreshLayout getFlavorSwipeLayout() {
        return (SwipeRefreshLayout) this.flavorSwipeLayout.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_ordinary;
    }

    @NotNull
    public final LinearLayout getLl_orderBy() {
        return (LinearLayout) this.ll_orderBy.getValue();
    }

    @NotNull
    public final LinearLayout getLl_tag() {
        return (LinearLayout) this.ll_tag.getValue();
    }

    @NotNull
    public final RelativeLayout getRl_parent() {
        return (RelativeLayout) this.rl_parent.getValue();
    }

    @NotNull
    public final RelativeLayout getRl_tagLayoutClick() {
        return (RelativeLayout) this.rl_tagLayoutClick.getValue();
    }

    @NotNull
    public final RecyclerView getRv_flavor() {
        return (RecyclerView) this.rv_flavor.getValue();
    }

    @NotNull
    public final TextView getTv_orderByName() {
        return (TextView) this.tv_orderByName.getValue();
    }

    @NotNull
    public final TopViewModel getViewModel() {
        return (TopViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    @SuppressLint({"NotifyDataSetChanged"})
    public void initViews() {
        super.initViews();
        getChildFragmentManager().beginTransaction().replace(R.id.frag_content, getMFragment()).commit();
        MainMenusBean mTabBean = getMTabBean();
        if (Intrinsics.areEqual(mTabBean == null ? null : mTabBean.type, "2")) {
            getLl_tag().setVisibility(0);
            RecyclerView rv_flavor = getRv_flavor();
            rv_flavor.setNestedScrollingEnabled(false);
            rv_flavor.setLayoutManager(new GridLayoutManager(requireContext(), 4));
            if (rv_flavor.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_flavor.getContext());
                c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_flavor, 5.0d);
                c4053a.f10337e = C2354n.m2437V(rv_flavor.getContext(), 5.0d);
                c4053a.f10339g = false;
                c4053a.f10340h = false;
                c4053a.f10338f = false;
                C1499a.m604Z(c4053a, rv_flavor);
            }
            rv_flavor.setAdapter(this.mTagAdapter);
        } else {
            getLl_tag().setVisibility(8);
        }
        TopViewModel viewModel = getViewModel();
        viewModel.loadInfo(true);
        viewModel.getTags().observe(this, new Observer() { // from class: b.a.a.a.t.g.k.i
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                OrdinaryFragment.m5833initViews$lambda2$lambda1(OrdinaryFragment.this, (List) obj);
            }
        });
        getApp_bar_layout().addOnOffsetChangedListener(new AppBarLayout.OnOffsetChangedListener() { // from class: b.a.a.a.t.g.k.h
            @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
            public final void onOffsetChanged(AppBarLayout appBarLayout, int i2) {
                OrdinaryFragment.m5834initViews$lambda3(OrdinaryFragment.this, appBarLayout, i2);
            }
        });
        SwipeRefreshLayout flavorSwipeLayout = getFlavorSwipeLayout();
        flavorSwipeLayout.setColorSchemeColors(flavorSwipeLayout.getResources().getColor(R.color.colorAccent));
        flavorSwipeLayout.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() { // from class: b.a.a.a.t.g.k.g
            @Override // androidx.swiperefreshlayout.widget.SwipeRefreshLayout.OnRefreshListener
            public final void onRefresh() {
                OrdinaryFragment.m5835initViews$lambda5$lambda4(OrdinaryFragment.this);
            }
        });
        C2354n.m2377B(getRl_tagLayoutClick(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$initViews$5
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull RelativeLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                OrdinaryFragment.this.showTagChooseDialog();
            }
        }, 1);
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        this.popup = new OrderByPopup(requireContext, new Function1<C0835a0, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$initViews$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(C0835a0 c0835a0) {
                invoke2(c0835a0);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull C0835a0 it) {
                HomeListFragment mFragment;
                Intrinsics.checkNotNullParameter(it, "it");
                OrdinaryFragment.this.curOrderBy = it;
                TextView tv_orderByName = OrdinaryFragment.this.getTv_orderByName();
                if (tv_orderByName != null) {
                    tv_orderByName.setText(it.f223b);
                }
                mFragment = OrdinaryFragment.this.getMFragment();
                mFragment.updateOrderBy(it.f222a);
            }
        });
        C2354n.m2377B(getLl_orderBy(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.OrdinaryFragment$initViews$7
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                OrderByPopup orderByPopup;
                OrderByPopup orderByPopup2;
                OrderByPopup orderByPopup3;
                C0835a0 c0835a0;
                OrderByPopup orderByPopup4;
                Intrinsics.checkNotNullParameter(it, "it");
                orderByPopup = OrdinaryFragment.this.popup;
                if (Intrinsics.areEqual(orderByPopup == null ? null : Boolean.valueOf(orderByPopup.isShowing()), Boolean.TRUE)) {
                    orderByPopup4 = OrdinaryFragment.this.popup;
                    if (orderByPopup4 == null) {
                        return;
                    }
                    orderByPopup4.dismiss();
                    return;
                }
                orderByPopup2 = OrdinaryFragment.this.popup;
                if (orderByPopup2 != null) {
                    c0835a0 = OrdinaryFragment.this.curOrderBy;
                    orderByPopup2.updateCurOrderBy(c0835a0);
                }
                orderByPopup3 = OrdinaryFragment.this.popup;
                if (orderByPopup3 == null) {
                    return;
                }
                orderByPopup3.showAsDropDown(OrdinaryFragment.this.getTv_orderByName());
            }
        }, 1);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public TopViewModel viewModelInstance() {
        return getViewModel();
    }
}
