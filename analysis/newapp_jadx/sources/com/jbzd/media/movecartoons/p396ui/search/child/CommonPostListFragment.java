package com.jbzd.media.movecartoons.p396ui.search.child;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.flexbox.FlexboxLayoutManager;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.event.EventSubscription;
import com.jbzd.media.movecartoons.bean.response.FilterData;
import com.jbzd.media.movecartoons.bean.response.LibraryBean;
import com.jbzd.media.movecartoons.bean.response.PostDetailBean;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.bean.response.ProfileBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostDetailActivity;
import com.jbzd.media.movecartoons.p396ui.post.user.UserPostHomeActivity;
import com.jbzd.media.movecartoons.p396ui.search.adapter.CheckChange;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment;
import com.jbzd.media.movecartoons.p396ui.search.model.SearchInfoModel;
import com.jbzd.media.movecartoons.p396ui.search.recyclerview.SearchView;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.view.CustomUserView;
import com.jbzd.media.movecartoons.view.ExpandableTextView;
import com.jbzd.media.movecartoons.view.XDividerItemDecoration;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p081b0.p082a.p083a.C1325b;
import p005b.p081b0.p082a.p083a.EnumC1326c;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u008c\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010 \n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u001c\b\u0016\u0018\u0000 j2\u00020\u0001:\u0002jkB\u0007¢\u0006\u0004\bi\u0010\rJ\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\r\u0010\n\u001a\u00020\t¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\f\u0010\rJ1\u0010\u0012\u001a\u00020\u00062\"\u0010\u0011\u001a\u001e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u000f0\u000ej\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u000f`\u0010¢\u0006\u0004\b\u0012\u0010\u0013J\u001f\u0010\u0016\u001a\u00020\u00062\u000e\u0010\u0015\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0014H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J+\u0010\u0018\u001a\u001e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u000f0\u000ej\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u000f`\u0010H\u0016¢\u0006\u0004\b\u0018\u0010\u0019J\u000f\u0010\u001b\u001a\u00020\u001aH\u0016¢\u0006\u0004\b\u001b\u0010\u001cJ\u0019\u0010\u001f\u001a\u00020\u00062\b\u0010\u001e\u001a\u0004\u0018\u00010\u001dH\u0007¢\u0006\u0004\b\u001f\u0010 J\u001f\u0010$\u001a\u00020\u00062\u0006\u0010\"\u001a\u00020!2\u0006\u0010#\u001a\u00020\u0004H\u0016¢\u0006\u0004\b$\u0010%J3\u0010)\u001a\u00020\u00062\u0012\u0010'\u001a\u000e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020!0&2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010(\u001a\u00020\u001aH\u0016¢\u0006\u0004\b)\u0010*J\u000f\u0010,\u001a\u00020+H\u0016¢\u0006\u0004\b,\u0010-J\u000f\u0010.\u001a\u00020\u000fH\u0016¢\u0006\u0004\b.\u0010/J\u0011\u00101\u001a\u0004\u0018\u000100H\u0016¢\u0006\u0004\b1\u00102R\"\u00103\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b3\u00104\u001a\u0004\b5\u0010/\"\u0004\b6\u00107R\"\u00108\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b8\u00104\u001a\u0004\b9\u0010/\"\u0004\b:\u00107R\u001d\u0010@\u001a\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b<\u0010=\u001a\u0004\b>\u0010?R\u001d\u0010E\u001a\u00020A8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bB\u0010=\u001a\u0004\bC\u0010DR\u001d\u0010H\u001a\u00020\t8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bF\u0010=\u001a\u0004\bG\u0010\u000bR\u001f\u0010K\u001a\u0004\u0018\u00010I8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bJ\u0010=\u001a\u0004\bK\u0010LR\u001d\u0010O\u001a\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bM\u0010=\u001a\u0004\bN\u0010?R\u001d\u0010T\u001a\u00020P8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bQ\u0010=\u001a\u0004\bR\u0010SR\u001c\u0010U\u001a\u00020\u000f8\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\bU\u00104\u001a\u0004\bV\u0010/R\u001d\u0010Y\u001a\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bW\u0010=\u001a\u0004\bX\u0010?R)\u0010\\\u001a\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u000f0\u000e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bZ\u0010=\u001a\u0004\b[\u0010\u0019R\"\u0010]\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b]\u00104\u001a\u0004\b^\u0010/\"\u0004\b_\u00107R\u001d\u0010b\u001a\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b`\u0010=\u001a\u0004\ba\u0010?R\"\u0010c\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bc\u00104\u001a\u0004\bd\u0010/\"\u0004\be\u00107R\u001f\u0010h\u001a\u0004\u0018\u00010\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bf\u0010=\u001a\u0004\bg\u0010/¨\u0006l"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/BaseCommonPostListFragment;", "Landroid/view/View;", "view", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "postListBean", "", "setFollowView", "(Landroid/view/View;Lcom/jbzd/media/movecartoons/bean/response/PostListBean;)V", "Lcom/jbzd/media/movecartoons/ui/search/model/SearchInfoModel;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/SearchInfoModel;", "initEvents", "()V", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "body", "requestData", "(Ljava/util/HashMap;)V", "", "t", "didRequestComplete", "(Ljava/util/List;)V", "getRequestBody", "()Ljava/util/HashMap;", "", "getItemLayoutId", "()I", "Lcom/jbzd/media/movecartoons/bean/event/EventSubscription;", NotificationCompat.CATEGORY_EVENT, "onMessageEvent", "(Lcom/jbzd/media/movecartoons/bean/event/EventSubscription;)V", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostListBean;)V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getEmptyTips", "()Ljava/lang/String;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "IS_SEARCH", "Ljava/lang/String;", "getIS_SEARCH", "setIS_SEARCH", "(Ljava/lang/String;)V", "intoType", "getIntoType", "setIntoType", "Lcom/jbzd/media/movecartoons/ui/search/recyclerview/SearchView;", "rv_type_1$delegate", "Lkotlin/Lazy;", "getRv_type_1", "()Lcom/jbzd/media/movecartoons/ui/search/recyclerview/SearchView;", "rv_type_1", "Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;", "swipeLayout$delegate", "getSwipeLayout", "()Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;", "swipeLayout", "viewModel$delegate", "getViewModel", "viewModel", "", "isSearch$delegate", "isSearch", "()Ljava/lang/Boolean;", "rv_type_2$delegate", "getRv_type_2", "rv_type_2", "Landroid/widget/LinearLayout;", "ll_post_filter$delegate", "getLl_post_filter", "()Landroid/widget/LinearLayout;", "ll_post_filter", "FILTER_PARAMS", "getFILTER_PARAMS", "rv_type_3$delegate", "getRv_type_3", "rv_type_3", "mapFilter$delegate", "getMapFilter", "mapFilter", "userId", "getUserId", "setUserId", "rv_type_4$delegate", "getRv_type_4", "rv_type_4", "IMG_URL", "getIMG_URL", "setIMG_URL", "img_url$delegate", "getImg_url", "img_url", "<init>", "Companion", "SearchCheck", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public class CommonPostListFragment extends BaseCommonPostListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private final String FILTER_PARAMS;

    @NotNull
    private String IMG_URL;

    @NotNull
    private String IS_SEARCH;

    /* renamed from: img_url$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy img_url;

    @NotNull
    private String intoType;

    /* renamed from: isSearch$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy isSearch;

    /* renamed from: ll_post_filter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_post_filter;

    /* renamed from: mapFilter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mapFilter;

    /* renamed from: rv_type_1$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_type_1;

    /* renamed from: rv_type_2$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_type_2;

    /* renamed from: rv_type_3$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_type_3;

    /* renamed from: rv_type_4$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_type_4;

    /* renamed from: swipeLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy swipeLayout;

    @NotNull
    private String userId;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ7\u0010\t\u001a\u00020\b2\u0016\b\u0002\u0010\u0004\u001a\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u00022\b\b\u0002\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u0003¢\u0006\u0004\b\t\u0010\n¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment$Companion;", "", "Ljava/util/HashMap;", "", "map", "", "search", "urlTop", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "newInstance", "(Ljava/util/HashMap;ZLjava/lang/String;)Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ CommonPostListFragment newInstance$default(Companion companion, HashMap hashMap, boolean z, String str, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                hashMap = null;
            }
            if ((i2 & 2) != 0) {
                z = false;
            }
            return companion.newInstance(hashMap, z, str);
        }

        @NotNull
        public final CommonPostListFragment newInstance(@Nullable HashMap<String, String> map, boolean search, @NotNull String urlTop) {
            Intrinsics.checkNotNullParameter(urlTop, "urlTop");
            CommonPostListFragment commonPostListFragment = new CommonPostListFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable(commonPostListFragment.getFILTER_PARAMS(), map);
            bundle.putBoolean(commonPostListFragment.getIS_SEARCH(), search);
            bundle.putString(commonPostListFragment.getIMG_URL(), urlTop);
            Unit unit = Unit.INSTANCE;
            commonPostListFragment.setArguments(bundle);
            return commonPostListFragment;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\f\u001a\u00020\u000b¢\u0006\u0004\b\u0016\u0010\u0017J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\t\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\t\u0010\nR\"\u0010\f\u001a\u00020\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R\"\u0010\u0003\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0003\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014\"\u0004\b\u0015\u0010\u0006¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment$SearchCheck;", "Lcom/jbzd/media/movecartoons/ui/search/adapter/CheckChange;", "Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;", "bean", "", "doSearch", "(Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;)V", "Lcom/jbzd/media/movecartoons/bean/response/FilterData;", "item", "change", "(Lcom/jbzd/media/movecartoons/bean/response/FilterData;)V", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "mCommonPostListFragment", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "getMCommonPostListFragment", "()Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "setMCommonPostListFragment", "(Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;)V", "Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;", "getBean", "()Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;", "setBean", "<init>", "(Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class SearchCheck extends CheckChange {

        @NotNull
        private LibraryBean bean;

        @NotNull
        private CommonPostListFragment mCommonPostListFragment;

        public SearchCheck(@NotNull LibraryBean bean, @NotNull CommonPostListFragment mCommonPostListFragment) {
            Intrinsics.checkNotNullParameter(bean, "bean");
            Intrinsics.checkNotNullParameter(mCommonPostListFragment, "mCommonPostListFragment");
            this.bean = bean;
            this.mCommonPostListFragment = mCommonPostListFragment;
        }

        @Override // com.jbzd.media.movecartoons.p396ui.search.adapter.CheckChange
        public void change(@NotNull FilterData item) {
            Intrinsics.checkNotNullParameter(item, "item");
            doSearch(this.bean);
        }

        @SuppressLint({"SuspiciousIndentation"})
        public final void doSearch(@NotNull LibraryBean bean) {
            Intrinsics.checkNotNullParameter(bean, "bean");
            HashMap<String, String> hashMap = new HashMap<>();
            List<FilterData> list = bean.one;
            Intrinsics.checkNotNullExpressionValue(list, "bean.one");
            for (FilterData filterData : list) {
                if (filterData.isSelected) {
                    String code = filterData.getCode();
                    Intrinsics.checkNotNullExpressionValue(code, "it.code");
                    String value = filterData.getValue();
                    Intrinsics.checkNotNullExpressionValue(value, "it.value");
                    hashMap.put(code, value);
                }
            }
            List<FilterData> list2 = bean.two;
            Intrinsics.checkNotNullExpressionValue(list2, "bean.two");
            for (FilterData filterData2 : list2) {
                if (filterData2.isSelected) {
                    String code2 = filterData2.getCode();
                    Intrinsics.checkNotNullExpressionValue(code2, "it.code");
                    String value2 = filterData2.getValue();
                    Intrinsics.checkNotNullExpressionValue(value2, "it.value");
                    hashMap.put(code2, value2);
                }
            }
            List<FilterData> list3 = bean.three;
            Intrinsics.checkNotNullExpressionValue(list3, "bean.three");
            for (FilterData filterData3 : list3) {
                if (filterData3.isSelected) {
                    String code3 = filterData3.getCode();
                    Intrinsics.checkNotNullExpressionValue(code3, "it.code");
                    String value3 = filterData3.getValue();
                    Intrinsics.checkNotNullExpressionValue(value3, "it.value");
                    hashMap.put(code3, value3);
                }
            }
            List<FilterData> list4 = bean.four;
            Intrinsics.checkNotNullExpressionValue(list4, "bean.four");
            for (FilterData filterData4 : list4) {
                if (filterData4.isSelected) {
                    String code4 = filterData4.getCode();
                    Intrinsics.checkNotNullExpressionValue(code4, "it.code");
                    String value4 = filterData4.getValue();
                    Intrinsics.checkNotNullExpressionValue(value4, "it.value");
                    hashMap.put(code4, value4);
                }
            }
            this.mCommonPostListFragment.requestData(hashMap);
        }

        @NotNull
        public final LibraryBean getBean() {
            return this.bean;
        }

        @NotNull
        public final CommonPostListFragment getMCommonPostListFragment() {
            return this.mCommonPostListFragment;
        }

        public final void setBean(@NotNull LibraryBean libraryBean) {
            Intrinsics.checkNotNullParameter(libraryBean, "<set-?>");
            this.bean = libraryBean;
        }

        public final void setMCommonPostListFragment(@NotNull CommonPostListFragment commonPostListFragment) {
            Intrinsics.checkNotNullParameter(commonPostListFragment, "<set-?>");
            this.mCommonPostListFragment = commonPostListFragment;
        }
    }

    public CommonPostListFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$special$$inlined$viewModels$default$1
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
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(SearchInfoModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$special$$inlined$viewModels$default$2
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
        this.userId = "";
        this.intoType = "";
        this.FILTER_PARAMS = "filter";
        this.IMG_URL = "urltop";
        this.IS_SEARCH = "search";
        this.mapFilter = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$mapFilter$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final HashMap<String, String> invoke() {
                Bundle arguments = CommonPostListFragment.this.getArguments();
                HashMap<String, String> hashMap = (HashMap) (arguments == null ? null : arguments.getSerializable(CommonPostListFragment.this.getFILTER_PARAMS()));
                return hashMap == null ? new HashMap<>() : hashMap;
            }
        });
        this.img_url = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$img_url$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @Nullable
            public final String invoke() {
                Bundle arguments = CommonPostListFragment.this.getArguments();
                if (arguments == null) {
                    return null;
                }
                return arguments.getString(CommonPostListFragment.this.getIMG_URL());
            }
        });
        this.isSearch = LazyKt__LazyJVMKt.lazy(new Function0<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$isSearch$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @Nullable
            public final Boolean invoke() {
                Bundle arguments = CommonPostListFragment.this.getArguments();
                if (arguments == null) {
                    return null;
                }
                return Boolean.valueOf(arguments.getBoolean(CommonPostListFragment.this.getIS_SEARCH()));
            }
        });
        this.ll_post_filter = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$ll_post_filter$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = CommonPostListFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_post_filter);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.rv_type_1 = LazyKt__LazyJVMKt.lazy(new Function0<SearchView>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$rv_type_1$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final SearchView invoke() {
                View view = CommonPostListFragment.this.getView();
                SearchView searchView = view == null ? null : (SearchView) view.findViewById(R.id.rv_type_1);
                Intrinsics.checkNotNull(searchView);
                return searchView;
            }
        });
        this.rv_type_2 = LazyKt__LazyJVMKt.lazy(new Function0<SearchView>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$rv_type_2$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final SearchView invoke() {
                View view = CommonPostListFragment.this.getView();
                SearchView searchView = view == null ? null : (SearchView) view.findViewById(R.id.rv_type_2);
                Intrinsics.checkNotNull(searchView);
                return searchView;
            }
        });
        this.rv_type_3 = LazyKt__LazyJVMKt.lazy(new Function0<SearchView>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$rv_type_3$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final SearchView invoke() {
                View view = CommonPostListFragment.this.getView();
                SearchView searchView = view == null ? null : (SearchView) view.findViewById(R.id.rv_type_3);
                Intrinsics.checkNotNull(searchView);
                return searchView;
            }
        });
        this.rv_type_4 = LazyKt__LazyJVMKt.lazy(new Function0<SearchView>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$rv_type_4$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final SearchView invoke() {
                View view = CommonPostListFragment.this.getView();
                SearchView searchView = view == null ? null : (SearchView) view.findViewById(R.id.rv_type_4);
                Intrinsics.checkNotNull(searchView);
                return searchView;
            }
        });
        this.swipeLayout = LazyKt__LazyJVMKt.lazy(new Function0<SwipeRefreshLayout>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$swipeLayout$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final SwipeRefreshLayout invoke() {
                View view = CommonPostListFragment.this.getView();
                SwipeRefreshLayout swipeRefreshLayout = view == null ? null : (SwipeRefreshLayout) view.findViewById(R.id.swipeLayout);
                Intrinsics.checkNotNull(swipeRefreshLayout);
                return swipeRefreshLayout;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindItem$lambda-11$lambda-7$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5984bindItem$lambda11$lambda7$lambda5$lambda4(CommonPostListFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
        PostCategoryDetailActivity.Companion companion = PostCategoryDetailActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String str = ((TagBean) obj).f10032id;
        Intrinsics.checkNotNullExpressionValue(str, "item.id");
        companion.start(requireContext, str, "normal");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initEvents$lambda-0, reason: not valid java name */
    public static final void m5985initEvents$lambda0(CommonPostListFragment this$0, HashMap hashMap) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        LibraryBean libraryBean = new LibraryBean();
        Collection<ArrayList<FilterData>> values = this$0.getViewModel().getListMap().values();
        Intrinsics.checkNotNullExpressionValue(values, "viewModel.listMap.values");
        ArrayList arrayList = new ArrayList(values);
        if (arrayList.size() == 4) {
            libraryBean.one = (List) arrayList.get(0);
            libraryBean.two = (List) arrayList.get(1);
            libraryBean.three = (List) arrayList.get(2);
            libraryBean.four = (List) arrayList.get(3);
            libraryBean.one.get(0).isSelected = true;
            libraryBean.two.get(0).isSelected = true;
            libraryBean.three.get(0).isSelected = true;
            libraryBean.four.get(0).isSelected = true;
            this$0.getRv_type_1().getAdapter().setNewData(libraryBean.one);
            this$0.getRv_type_2().getAdapter().setNewData(libraryBean.two);
            this$0.getRv_type_3().getAdapter().setNewData(libraryBean.three);
            this$0.getRv_type_4().getAdapter().setNewData(libraryBean.four);
            SearchCheck searchCheck = new SearchCheck(libraryBean, this$0);
            this$0.getRv_type_1().getAdapter().setChange(searchCheck);
            this$0.getRv_type_2().getAdapter().setChange(searchCheck);
            this$0.getRv_type_3().getAdapter().setChange(searchCheck);
            this$0.getRv_type_4().getAdapter().setChange(searchCheck);
            searchCheck.doSearch(libraryBean);
        }
        if (arrayList.size() == 3) {
            libraryBean.one = (List) arrayList.get(0);
            libraryBean.two = (List) arrayList.get(1);
            libraryBean.three = (List) arrayList.get(2);
            libraryBean.one.get(0).isSelected = true;
            libraryBean.two.get(0).isSelected = true;
            libraryBean.three.get(0).isSelected = true;
            this$0.getRv_type_1().getAdapter().setNewData(libraryBean.one);
            this$0.getRv_type_2().getAdapter().setNewData(libraryBean.two);
            this$0.getRv_type_3().getAdapter().setNewData(libraryBean.three);
            SearchCheck searchCheck2 = new SearchCheck(libraryBean, this$0);
            this$0.getRv_type_1().getAdapter().setChange(searchCheck2);
            this$0.getRv_type_2().getAdapter().setChange(searchCheck2);
            this$0.getRv_type_3().getAdapter().setChange(searchCheck2);
            this$0.getRv_type_4().setVisibility(8);
            searchCheck2.doSearch(libraryBean);
        }
    }

    private final Boolean isSearch() {
        return (Boolean) this.isSearch.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setFollowView(View view, PostListBean postListBean) {
        ((TextView) view).setText(Intrinsics.areEqual(postListBean.user.is_follow, "y") ? "已关注" : "+关注");
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void didRequestComplete(@Nullable List<? extends PostListBean> t) {
        SwipeRefreshLayout swipeLayout = getSwipeLayout();
        if (swipeLayout != null) {
            swipeLayout.setRefreshing(false);
        }
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m334k(true);
        }
        if (getCurrentPage() == 1) {
            if (t == null || t.isEmpty()) {
                getAdapter().setNewData(null);
                showEmptyDataView();
                return;
            } else {
                getAdapter().removeEmptyView();
                BaseQuickAdapter<PostListBean, BaseViewHolder> adapter = getAdapter();
                Objects.requireNonNull(t, "null cannot be cast to non-null type java.util.ArrayList<com.jbzd.media.movecartoons.bean.response.PostListBean>");
                adapter.setNewData((ArrayList) t);
                return;
            }
        }
        C1318f loadMoreModule2 = getAdapter().getLoadMoreModule();
        if (loadMoreModule2 != null) {
            loadMoreModule2.m330f();
        }
        if (!(t == null || t.isEmpty())) {
            getAdapter().addData(t);
            return;
        }
        C1318f loadMoreModule3 = getAdapter().getLoadMoreModule();
        if (loadMoreModule3 == null) {
            return;
        }
        C1318f.m324h(loadMoreModule3, false, 1, null);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public String getEmptyTips() {
        return "当前页面暂无内容";
    }

    @NotNull
    public final String getFILTER_PARAMS() {
        return this.FILTER_PARAMS;
    }

    @NotNull
    public final String getIMG_URL() {
        return this.IMG_URL;
    }

    @NotNull
    public final String getIS_SEARCH() {
        return this.IS_SEARCH;
    }

    @Nullable
    public final String getImg_url() {
        return (String) this.img_url.getValue();
    }

    @NotNull
    public final String getIntoType() {
        return this.intoType;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        XDividerItemDecoration xDividerItemDecoration = new XDividerItemDecoration(getContext(), 1);
        xDividerItemDecoration.setDrawable(getResources().getDrawable(R.drawable.divider_line_post));
        return xDividerItemDecoration;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_posthome_postitem;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new LinearLayoutManager(requireContext(), 1, false);
    }

    @NotNull
    public final LinearLayout getLl_post_filter() {
        return (LinearLayout) this.ll_post_filter.getValue();
    }

    @NotNull
    public final HashMap<String, String> getMapFilter() {
        return (HashMap) this.mapFilter.getValue();
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment
    @NotNull
    public HashMap<String, String> getRequestBody() {
        Bundle arguments = getArguments();
        HashMap<String, String> hashMap = (HashMap) (arguments == null ? null : arguments.getSerializable("params_map"));
        if (hashMap == null) {
            hashMap = createEmptyRequestBody();
        }
        HashMap<String, String> mapFilter = getMapFilter();
        if (mapFilter != null) {
            hashMap.putAll(mapFilter);
        }
        return hashMap;
    }

    @NotNull
    public final SearchView getRv_type_1() {
        return (SearchView) this.rv_type_1.getValue();
    }

    @NotNull
    public final SearchView getRv_type_2() {
        return (SearchView) this.rv_type_2.getValue();
    }

    @NotNull
    public final SearchView getRv_type_3() {
        return (SearchView) this.rv_type_3.getValue();
    }

    @NotNull
    public final SearchView getRv_type_4() {
        return (SearchView) this.rv_type_4.getValue();
    }

    @NotNull
    public final SwipeRefreshLayout getSwipeLayout() {
        return (SwipeRefreshLayout) this.swipeLayout.getValue();
    }

    @NotNull
    public final String getUserId() {
        return this.userId;
    }

    @NotNull
    public final SearchInfoModel getViewModel() {
        return (SearchInfoModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        super.initEvents();
        if (Intrinsics.areEqual(isSearch(), Boolean.TRUE)) {
            getLl_post_filter().setVisibility(0);
            SearchInfoModel.postFilter$default(getViewModel(), false, 1, null);
            getViewModel().getFilterData().observe(getViewLifecycleOwner(), new Observer() { // from class: b.a.a.a.t.m.j.a
                @Override // androidx.lifecycle.Observer
                public final void onChanged(Object obj) {
                    CommonPostListFragment.m5985initEvents$lambda0(CommonPostListFragment.this, (HashMap) obj);
                }
            });
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemClick(@NotNull BaseQuickAdapter<PostListBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        adapter.getData().get(position);
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onMessageEvent(@Nullable EventSubscription event) {
        getView();
        if (event != null) {
            String userId = event.getUserId();
            for (PostListBean postListBean : getAdapter().getData()) {
                if (Intrinsics.areEqual(postListBean.user.f9982id, userId)) {
                    postListBean.user.is_follow = event.getStatus();
                    getAdapter().notifyDataSetChanged();
                }
            }
        }
    }

    public final void requestData(@NotNull HashMap<String, String> body) {
        Intrinsics.checkNotNullParameter(body, "body");
        getRequestRoomParameter().clear();
        getRequestRoomParameter().putAll(body);
        request();
    }

    public final void setIMG_URL(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.IMG_URL = str;
    }

    public final void setIS_SEARCH(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.IS_SEARCH = str;
    }

    public final void setIntoType(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.intoType = str;
    }

    public final void setUserId(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.userId = str;
    }

    @NotNull
    public final SearchInfoModel viewModelInstance() {
        return getViewModel();
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull final BaseViewHolder helper, @NotNull final PostListBean item) {
        int i2;
        int i3;
        String str;
        Resources resources;
        int i4;
        EnumC1326c enumC1326c = EnumC1326c.IMAGE;
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        LinearLayout linearLayout = (LinearLayout) helper.m3912b(R.id.ll_mypost_time_del);
        linearLayout.setVisibility(8);
        TextView textView = (TextView) helper.m3912b(R.id.tv_mypost_time);
        textView.setText(Intrinsics.stringPlus("发布时间 ", item.time));
        RecyclerView recyclerView = (RecyclerView) helper.m3912b(R.id.rv_tag_post);
        BaseQuickAdapter<TagBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$1$1
            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper2, @NotNull TagBean item2) {
                Intrinsics.checkNotNullParameter(helper2, "helper");
                Intrinsics.checkNotNullParameter(item2, "item");
                helper2.m3919i(R.id.tv_content, Intrinsics.stringPlus("#", item2.name));
                helper2.itemView.setTag(item2.f10032id);
            }
        };
        baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.m.j.b
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i5) {
                CommonPostListFragment.m5984bindItem$lambda11$lambda7$lambda5$lambda4(CommonPostListFragment.this, baseQuickAdapter2, view, i5);
            }
        });
        baseQuickAdapter.setNewData(item.categories);
        Unit unit = Unit.INSTANCE;
        recyclerView.setAdapter(baseQuickAdapter);
        FlexboxLayoutManager flexboxLayoutManager = new FlexboxLayoutManager(recyclerView.getContext());
        flexboxLayoutManager.m4176y(1);
        flexboxLayoutManager.m4175x(0);
        recyclerView.setLayoutManager(flexboxLayoutManager);
        if (recyclerView.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(recyclerView.getContext());
            c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, recyclerView, 2.0d);
            c4053a.f10337e = C2354n.m2437V(recyclerView.getContext(), 3.0d);
            C1499a.m604Z(c4053a, recyclerView);
        }
        PostListBean.UserBean userBean = item.user;
        ((CustomUserView) helper.m3912b(R.id.profile)).setUserInfo(new ProfileBean(userBean.nickname, userBean.is_vip, userBean.is_up));
        LinearLayout linearLayout2 = (LinearLayout) helper.m3912b(R.id.ll_posthome_usertop);
        String str2 = item.user.f9982id;
        MyApp myApp = MyApp.f9891f;
        if (Intrinsics.areEqual(str2, MyApp.f9892g.user_id)) {
            linearLayout2.setVisibility(8);
        } else {
            C2354n.m2374A(linearLayout2, 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$2
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout3) {
                    invoke2(linearLayout3);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull LinearLayout it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    UserPostHomeActivity.Companion companion = UserPostHomeActivity.Companion;
                    Context requireContext = CommonPostListFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    String str3 = item.user.f9982id;
                    Intrinsics.checkNotNullExpressionValue(str3, "item.user.id");
                    companion.start(requireContext, str3);
                }
            }, 1);
        }
        ExpandableTextView expandableTextView = (ExpandableTextView) helper.m3912b(R.id.tv_posthome_content);
        AppCompatTextView appCompatTextView = (AppCompatTextView) helper.m3912b(R.id.tv_posthome_childitemtitle);
        TextView textView2 = (TextView) helper.m3912b(R.id.tv_space_show);
        if (Intrinsics.areEqual(getIntoType(), "userPostHomePage")) {
            linearLayout2.setVisibility(8);
            textView2.setVisibility(8);
            appCompatTextView.setVisibility(0);
            appCompatTextView.setTextSize(15.0f);
            expandableTextView.setTextSize(15.0f);
            appCompatTextView.setTextColor(getResources().getColor(R.color.black));
            i2 = 1;
            appCompatTextView.getPaint().setFakeBoldText(true);
            linearLayout.setVisibility(0);
            textView.setVisibility(0);
        } else {
            i2 = 1;
        }
        C2354n.m2374A((LinearLayout) helper.m3912b(R.id.ll_postitem), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout3) {
                invoke2(linearLayout3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (!Intrinsics.areEqual(PostListBean.this.status, "1")) {
                    C2354n.m2449Z("该帖子未发布，不可查看详情");
                    return;
                }
                PostDetailActivity.Companion companion = PostDetailActivity.INSTANCE;
                Context requireContext = this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str3 = PostListBean.this.f9980id;
                Intrinsics.checkNotNullExpressionValue(str3, "item.id");
                companion.start(requireContext, str3);
            }
        }, i2);
        C2354n.m2374A(expandableTextView, 0L, new Function1<ExpandableTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ExpandableTextView expandableTextView2) {
                invoke2(expandableTextView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ExpandableTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (!Intrinsics.areEqual(PostListBean.this.status, "1")) {
                    C2354n.m2449Z("该帖子未发布，不可查看详情");
                    return;
                }
                PostDetailActivity.Companion companion = PostDetailActivity.INSTANCE;
                Context requireContext = this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str3 = PostListBean.this.f9980id;
                Intrinsics.checkNotNullExpressionValue(str3, "item.id");
                companion.start(requireContext, str3);
            }
        }, i2);
        C2354n.m2374A(appCompatTextView, 0L, new Function1<AppCompatTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$5
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(AppCompatTextView appCompatTextView2) {
                invoke2(appCompatTextView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull AppCompatTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (!Intrinsics.areEqual(PostListBean.this.status, "1")) {
                    C2354n.m2449Z("该帖子未发布，不可查看详情");
                    return;
                }
                PostDetailActivity.Companion companion = PostDetailActivity.INSTANCE;
                Context requireContext = this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str3 = PostListBean.this.f9980id;
                Intrinsics.checkNotNullExpressionValue(str3, "item.id");
                companion.start(requireContext, str3);
            }
        }, i2);
        LinearLayout linearLayout3 = (LinearLayout) helper.m3912b(R.id.ll_community_img_three);
        LinearLayout linearLayout4 = (LinearLayout) helper.m3912b(R.id.ll_community_img_two);
        RelativeLayout relativeLayout = (RelativeLayout) helper.m3912b(R.id.ll_postitem_one);
        if (Intrinsics.areEqual(item.user.f9982id, getUserId())) {
            i3 = 1;
            helper.m3916f(R.id.itv_postuser_follow, true);
        } else {
            i3 = 1;
            helper.m3916f(R.id.itv_postuser_follow, false);
        }
        C2354n.m2374A(helper.m3912b(R.id.itv_postuser_follow), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$6
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView3) {
                invoke2(textView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                List<PostListBean> data = CommonPostListFragment.this.getAdapter().getData();
                CommonPostListFragment commonPostListFragment = CommonPostListFragment.this;
                BaseViewHolder baseViewHolder = helper;
                for (PostListBean postListBean : data) {
                    if (Intrinsics.areEqual(postListBean.user.f9982id, commonPostListFragment.getAdapter().getItem(baseViewHolder.getAdapterPosition()).user.f9982id)) {
                        if (Intrinsics.areEqual(postListBean.user.is_follow, "n")) {
                            postListBean.user.is_follow = "y";
                        } else {
                            postListBean.user.is_follow = "n";
                        }
                        commonPostListFragment.setFollowView(it, commonPostListFragment.getAdapter().getItem(baseViewHolder.getAdapterPosition()));
                    }
                }
                CommonPostListFragment.this.getAdapter().notifyDataSetChanged();
                HashMap hashMap = new HashMap();
                String str3 = item.user.f9982id;
                Intrinsics.checkNotNullExpressionValue(str3, "item.user.id");
                hashMap.put("id", str3);
                C0917a c0917a = C0917a.f372a;
                final PostListBean postListBean2 = item;
                C0917a.m221e(c0917a, "user/doFollow", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$6.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(String str4) {
                        invoke2(str4);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable String str4) {
                        C4909c m5569b = C4909c.m5569b();
                        String str5 = PostListBean.this.user.f9982id;
                        String valueOf = String.valueOf(str4);
                        HashMap hashMap2 = new HashMap();
                        if (!(valueOf.length() == 0)) {
                            try {
                                JSONObject jSONObject = new JSONObject(valueOf);
                                Iterator<String> keys = jSONObject.keys();
                                while (keys.hasNext()) {
                                    String key = keys.next();
                                    String value = jSONObject.getString(key);
                                    Intrinsics.checkNotNullExpressionValue(key, "key");
                                    Intrinsics.checkNotNullExpressionValue(value, "value");
                                    hashMap2.put(key, value);
                                }
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                        }
                        m5569b.m5574g(new EventSubscription(str5, (String) hashMap2.get(NotificationCompat.CATEGORY_STATUS)));
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$6.3
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                }, false, false, null, false, 480);
            }
        }, i3);
        List<PostDetailBean.FilesBean> list = item.files;
        if (list != null) {
            if (list.size() >= 3) {
                linearLayout3.setVisibility(0);
                linearLayout4.setVisibility(8);
                relativeLayout.setVisibility(8);
                ShapeableImageView view = (ShapeableImageView) helper.m3912b(R.id.iv_community_img_twolft_posthome);
                C2354n.m2455a2(requireContext()).m3298p(item.files.get(0).image).m3295i0().m757R(view);
                Intrinsics.checkNotNullParameter(view, "view");
                view.setOutlineProvider(new C0859m0(6.0d));
                view.setClipToOutline(true);
                ShapeableImageView view2 = (ShapeableImageView) helper.m3912b(R.id.iv_community_two_posthome);
                C2354n.m2455a2(requireContext()).m3298p(item.files.get(1).image).m3295i0().m757R(view2);
                Intrinsics.checkNotNullParameter(view2, "view");
                view2.setOutlineProvider(new C0859m0(6.0d));
                view2.setClipToOutline(true);
                ShapeableImageView view3 = (ShapeableImageView) helper.m3912b(R.id.iv_community_three_posthome);
                C2354n.m2455a2(requireContext()).m3298p(item.files.get(2).image).m3295i0().m757R(view3);
                Intrinsics.checkNotNullParameter(view3, "view");
                view3.setOutlineProvider(new C0859m0(6.0d));
                view3.setClipToOutline(true);
                if (Intrinsics.areEqual(item.files.get(2).type, "image")) {
                    helper.m3916f(R.id.iv_community_threevideo, true);
                } else {
                    helper.m3916f(R.id.iv_community_threevideo, false);
                }
                ((ImageTextView) helper.m3912b(R.id.itv_type_three_vip)).setVisibility(8);
                ((ImageView) helper.m3912b(R.id.itv_type_three_money)).setVisibility(8);
            } else if (item.files.size() == 2) {
                ImageView view4 = (ImageView) helper.m3912b(R.id.im_postdetail_two_left_);
                ImageView view5 = (ImageView) helper.m3912b(R.id.im_postdetail_two_right_);
                linearLayout3.setVisibility(8);
                linearLayout4.setVisibility(0);
                relativeLayout.setVisibility(8);
                C2354n.m2455a2(requireContext()).m3298p(item.files.get(0).image).m3295i0().m757R(view4);
                Intrinsics.checkNotNullParameter(view4, "view");
                view4.setOutlineProvider(new C0859m0(6.0d));
                view4.setClipToOutline(true);
                C2354n.m2455a2(requireContext()).m3298p(item.files.get(1).image).m3295i0().m757R(view5);
                Intrinsics.checkNotNullParameter(view5, "view");
                view5.setOutlineProvider(new C0859m0(6.0d));
                view5.setClipToOutline(true);
                if (Intrinsics.areEqual(item.files.get(1).type, "image")) {
                    helper.m3916f(R.id.iv_postdetail_two_type, true);
                } else {
                    helper.m3916f(R.id.iv_postdetail_two_type, false);
                }
                ((ImageTextView) helper.m3912b(R.id.itv_type_two_vip)).setVisibility(8);
                ((ImageView) helper.m3912b(R.id.itv_type_two_money)).setVisibility(8);
            } else if (item.files.size() == 1) {
                linearLayout3.setVisibility(8);
                linearLayout4.setVisibility(8);
                relativeLayout.setVisibility(0);
                ImageView view6 = (ImageView) helper.m3912b(R.id.im_community_img_single);
                C2354n.m2455a2(requireContext()).m3298p(item.files.get(0).image).m3295i0().m757R(view6);
                Intrinsics.checkNotNullParameter(view6, "view");
                view6.setOutlineProvider(new C0859m0(6.0d));
                view6.setClipToOutline(true);
                if (Intrinsics.areEqual(item.files.get(0).type, "image")) {
                    helper.m3916f(R.id.iv_postitem_pause, true);
                } else {
                    helper.m3916f(R.id.iv_postitem_pause, false);
                }
                ((ImageTextView) helper.m3912b(R.id.itv_type_one_vip)).setVisibility(8);
                ((ImageView) helper.m3912b(R.id.itv_type_one_money)).setVisibility(8);
            } else {
                linearLayout3.setVisibility(8);
                linearLayout4.setVisibility(8);
                relativeLayout.setVisibility(8);
            }
        }
        CircleImageView circleImageView = (CircleImageView) helper.m3912b(R.id.iv_userfollow_avatar);
        ApplicationC2828a context = C2827a.f7670a;
        if (context == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            PackageManager packageManager = context.getPackageManager();
            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
            str = (String) packageManager.getApplicationLabel(applicationInfo);
        } catch (PackageManager.NameNotFoundException unused) {
            str = "";
        }
        if (Intrinsics.areEqual(str != null ? Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(str, "九妖", false, 2, null)) : null, Boolean.TRUE)) {
            C2354n.m2455a2(requireContext()).m3297o(Integer.valueOf(R.drawable.ic_logo)).m3288b0().m757R(circleImageView);
        } else {
            C2354n.m2455a2(requireContext()).m3297o(Integer.valueOf(R.mipmap.ic_launcher_51)).m3288b0().m757R(circleImageView);
        }
        C2852c m2455a2 = C2354n.m2455a2(requireContext());
        String str3 = item.user.img;
        if (str3 == null) {
            str3 = "";
        }
        C1558h mo770c = m2455a2.mo770c();
        mo770c.mo763X(str3);
        ((C2851b) mo770c).m3288b0().m757R(circleImageView);
        helper.m3919i(R.id.tv_post_created_at, Intrinsics.stringPlus("发布时间 ", item.time));
        helper.m3919i(R.id.tv_posthome_childitemtitle, item.title);
        helper.m3919i(R.id.tv_posthome_content, item.content);
        helper.m3916f(R.id.tv_posthome_content, Intrinsics.areEqual(item.content, ""));
        helper.m3919i(R.id.itv_postuser_follow, Intrinsics.areEqual(item.user.is_follow, "y") ? "已关注" : "+关注");
        ((TextView) helper.m3912b(R.id.itv_postuser_follow)).setSelected(Intrinsics.areEqual(item.user.is_follow, "y"));
        helper.m3919i(R.id.itv_postitem_click, C0843e0.m182a(item.click));
        helper.m3919i(R.id.iv_count_comment, C0843e0.m182a(item.comment));
        ImageTextView imageTextView = (ImageTextView) helper.m3912b(R.id.itv_postitem_likes);
        helper.m3919i(R.id.itv_postitem_likes, C0843e0.m182a(item.love));
        imageTextView.setSelected(Intrinsics.areEqual(item.has_love, "y"));
        if (Intrinsics.areEqual(item.has_love, "y")) {
            resources = getResources();
            i4 = R.color.color_ff0000;
        } else {
            resources = getResources();
            i4 = R.color.black40;
        }
        helper.m3920j(R.id.itv_postitem_likes, resources.getColor(i4));
        C2354n.m2374A(helper.m3912b(R.id.ll_postitem_likes), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$7
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout5) {
                invoke2(linearLayout5);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                HashMap hashMap = new HashMap();
                String str4 = PostListBean.this.f9980id;
                Intrinsics.checkNotNullExpressionValue(str4, "item.id");
                hashMap.put("id", str4);
                C0917a c0917a = C0917a.f372a;
                final PostListBean postListBean = PostListBean.this;
                final CommonPostListFragment commonPostListFragment = this;
                C0917a.m221e(c0917a, "post/doLove", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$7.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(String str5) {
                        invoke2(str5);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable String str5) {
                        if (Intrinsics.areEqual(PostListBean.this.has_love, "y")) {
                            PostListBean postListBean2 = PostListBean.this;
                            Intrinsics.checkNotNullExpressionValue(postListBean2.love, "item.love");
                            postListBean2.love = String.valueOf(Integer.parseInt(r0) - 1);
                            PostListBean.this.has_love = "n";
                        } else {
                            PostListBean postListBean3 = PostListBean.this;
                            String str6 = postListBean3.love;
                            Intrinsics.checkNotNullExpressionValue(str6, "item.love");
                            postListBean3.love = String.valueOf(Integer.parseInt(str6) + 1);
                            PostListBean.this.has_love = "y";
                        }
                        commonPostListFragment.getAdapter().notifyDataSetChanged();
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$7.2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                }, false, false, null, false, 480);
            }
        }, 1);
        C2354n.m2374A(helper.m3912b(R.id.ll_postitem_comment), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$8
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout5) {
                invoke2(linearLayout5);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(PostListBean.this.status, "0")) {
                    C2354n.m2449Z("待审核帖子不能评论");
                    return;
                }
                PostDetailActivity.Companion companion = PostDetailActivity.INSTANCE;
                Context requireContext = this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str4 = PostListBean.this.f9980id;
                Intrinsics.checkNotNullExpressionValue(str4, "item.id");
                companion.start(requireContext, str4);
            }
        }, 1);
        C2354n.m2374A(helper.m3912b(R.id.ll_share_postitem), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$9
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout5) {
                invoke2(linearLayout5);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                InviteActivity.Companion companion = InviteActivity.INSTANCE;
                Context requireContext = CommonPostListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        AppCompatTextView appCompatTextView2 = (AppCompatTextView) helper.m3912b(R.id.tv_posthome_childitemtitle);
        if (Intrinsics.areEqual(item.is_hot, "y")) {
            C1325b c1325b = new C1325b(enumC1326c);
            c1325b.f1078E = appCompatTextView2.getResources().getDrawable(R.drawable.icon_jh);
            c1325b.f1081H = 10;
            C2354n.m2472f(appCompatTextView2, c1325b, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$10$1
                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                }
            });
        }
        if (Intrinsics.areEqual(item.is_top, "y")) {
            C1325b c1325b2 = new C1325b(enumC1326c);
            c1325b2.f1078E = appCompatTextView2.getResources().getDrawable(R.drawable.icon_top);
            c1325b2.f1081H = 10;
            C2354n.m2472f(appCompatTextView2, c1325b2, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$bindItem$1$10$2
                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                }
            });
        }
    }
}
