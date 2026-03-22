package com.jbzd.media.movecartoons.p396ui.novel;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.flexbox.FlexboxLayoutManager;
import com.google.android.material.imageview.ShapeableImageView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.Tags;
import com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.comics.CommentFragment;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.novel.NovelChapterViewActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailActivity$tagAdapter$2;
import com.jbzd.media.movecartoons.p396ui.search.ComicsModuleDetailActivity;
import com.jbzd.media.movecartoons.p396ui.search.model.ComicsViewModel;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p258c.C2480j;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000½\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0019\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0010\u000e\n\u0002\b\u0015\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002*\u0001:\u0018\u0000 \u009d\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u009d\u0001B\b¢\u0006\u0005\b\u009c\u0001\u0010\u000eJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\r\u0010\b\u001a\u00020\u0002¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u0019\u0010\u0011\u001a\u00020\u00052\b\u0010\u0010\u001a\u0004\u0018\u00010\u000fH\u0014¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0005H\u0014¢\u0006\u0004\b\u0013\u0010\u000eR\u001d\u0010\u0019\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001e\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0016\u001a\u0004\b\u001c\u0010\u001dR\"\u0010 \u001a\u00020\u001f8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b \u0010!\u001a\u0004\b\"\u0010#\"\u0004\b$\u0010%R\u001d\u0010*\u001a\u00020&8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u0016\u001a\u0004\b(\u0010)R\u001d\u0010/\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u0016\u001a\u0004\b-\u0010.R\u001d\u00104\u001a\u0002008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b1\u0010\u0016\u001a\u0004\b2\u00103R\u001d\u00109\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u0016\u001a\u0004\b7\u00108R\u001d\u0010>\u001a\u00020:8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b;\u0010\u0016\u001a\u0004\b<\u0010=R\u001d\u0010C\u001a\u00020?8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b@\u0010\u0016\u001a\u0004\bA\u0010BR\u001d\u0010H\u001a\u00020D8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u0016\u001a\u0004\bF\u0010GR\u001d\u0010K\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010\u0016\u001a\u0004\bJ\u0010\u001dR\u001d\u0010N\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bL\u0010\u0016\u001a\u0004\bM\u00108R\u001d\u0010S\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bP\u0010\u0016\u001a\u0004\bQ\u0010RR\u001d\u0010V\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bT\u0010\u0016\u001a\u0004\bU\u00108R\u001d\u0010Y\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bW\u0010\u0016\u001a\u0004\bX\u0010\tR\u001d\u0010\\\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bZ\u0010\u0016\u001a\u0004\b[\u00108R\u001d\u0010_\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010\u0016\u001a\u0004\b^\u0010\u001dR\u001d\u0010b\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b`\u0010\u0016\u001a\u0004\ba\u0010\u001dR\u001d\u0010e\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bc\u0010\u0016\u001a\u0004\bd\u0010.R\u001d\u0010h\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bf\u0010\u0016\u001a\u0004\bg\u0010RR\u001d\u0010m\u001a\u00020i8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bj\u0010\u0016\u001a\u0004\bk\u0010lR\"\u0010o\u001a\u00020n8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bo\u0010p\u001a\u0004\bq\u0010r\"\u0004\bs\u0010tR\u001d\u0010w\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bu\u0010\u0016\u001a\u0004\bv\u00108R\u001d\u0010z\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bx\u0010\u0016\u001a\u0004\by\u0010\u001dR\u001d\u0010}\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b{\u0010\u0016\u001a\u0004\b|\u0010\u001dR\u001e\u0010\u0080\u0001\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b~\u0010\u0016\u001a\u0004\b\u007f\u00108R\u001c\u0010\u0082\u0001\u001a\u0005\u0018\u00010\u0081\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\b\u0082\u0001\u0010\u0083\u0001R \u0010\u0086\u0001\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0084\u0001\u0010\u0016\u001a\u0005\b\u0085\u0001\u00108R \u0010\u0089\u0001\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0087\u0001\u0010\u0016\u001a\u0005\b\u0088\u0001\u0010RR$\u0010\u008d\u0001\u001a\u0005\u0018\u00010\u0081\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u008a\u0001\u0010\u0016\u001a\u0006\b\u008b\u0001\u0010\u008c\u0001R \u0010\u0090\u0001\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u008e\u0001\u0010\u0016\u001a\u0005\b\u008f\u0001\u00108R \u0010\u0093\u0001\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0091\u0001\u0010\u0016\u001a\u0005\b\u0092\u0001\u0010RR \u0010\u0096\u0001\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0094\u0001\u0010\u0016\u001a\u0005\b\u0095\u0001\u0010RR\"\u0010\u009b\u0001\u001a\u00030\u0097\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0098\u0001\u0010\u0016\u001a\u0006\b\u0099\u0001\u0010\u009a\u0001¨\u0006¦\u0001²\u00069\u0010¢\u0001\u001a,\u0012\u0010\u0012\u000e\u0012\t\b\u0001\u0012\u0005\u0018\u00010 \u00010\u009f\u00010\u009e\u0001j\u0015\u0012\u0010\u0012\u000e\u0012\t\b\u0001\u0012\u0005\u0018\u00010 \u00010\u009f\u0001`¡\u00018\n@\nX\u008a\u0084\u0002²\u0006#\u0010£\u0001\u001a\u0016\u0012\u0005\u0012\u00030\u0081\u00010\u009e\u0001j\n\u0012\u0005\u0012\u00030\u0081\u0001`¡\u00018\n@\nX\u008a\u0084\u0002²\u0006\u0010\u0010¥\u0001\u001a\u00030¤\u00018\n@\nX\u008a\u0084\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "mNovelDetailInfoBean", "", "initView", "(Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;)V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "", "getLayoutId", "()I", "bindEvent", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "onDestroy", "Landroidx/appcompat/widget/AppCompatEditText;", "ed_input_comment_novel$delegate", "Lkotlin/Lazy;", "getEd_input_comment_novel", "()Landroidx/appcompat/widget/AppCompatEditText;", "ed_input_comment_novel", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_noveldetail_like$delegate", "getItv_noveldetail_like", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_noveldetail_like", "Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailInfoFragment;", "mNovelDetailInfoFragment", "Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailInfoFragment;", "getMNovelDetailInfoFragment", "()Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailInfoFragment;", "setMNovelDetailInfoFragment", "(Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailInfoFragment;)V", "Lcom/google/android/material/imageview/ShapeableImageView;", "iv_noveldetail_img$delegate", "getIv_noveldetail_img", "()Lcom/google/android/material/imageview/ShapeableImageView;", "iv_noveldetail_img", "Landroid/widget/ImageView;", "iv_noveldetail_top$delegate", "getIv_noveldetail_top", "()Landroid/widget/ImageView;", "iv_noveldetail_top", "Landroid/widget/RelativeLayout;", "btn_titleBack$delegate", "getBtn_titleBack", "()Landroid/widget/RelativeLayout;", "btn_titleBack", "Landroid/widget/TextView;", "tv_read_start$delegate", "getTv_read_start", "()Landroid/widget/TextView;", "tv_read_start", "com/jbzd/media/movecartoons/ui/novel/NovelDetailActivity$tagAdapter$2$1", "tagAdapter$delegate", "getTagAdapter", "()Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailActivity$tagAdapter$2$1;", "tagAdapter", "Landroidx/viewpager/widget/ViewPager;", "vp_noveldetail$delegate", "getVp_noveldetail", "()Landroidx/viewpager/widget/ViewPager;", "vp_noveldetail", "Lcom/jbzd/media/movecartoons/view/FollowTextView;", "tv_noveldetail_favorite$delegate", "getTv_noveldetail_favorite", "()Lcom/jbzd/media/movecartoons/view/FollowTextView;", "tv_noveldetail_favorite", "itv_noveldetial_commentnum$delegate", "getItv_noveldetial_commentnum", "itv_noveldetial_commentnum", "tv_noveldetail_name$delegate", "getTv_noveldetail_name", "tv_noveldetail_name", "Landroid/widget/LinearLayout;", "ll_noveldetail_bottom$delegate", "getLl_noveldetail_bottom", "()Landroid/widget/LinearLayout;", "ll_noveldetail_bottom", "tv_noveldetail_category$delegate", "getTv_noveldetail_category", "tv_noveldetail_category", "viewModel$delegate", "getViewModel", "viewModel", "tv_noveldetail_description$delegate", "getTv_noveldetail_description", "tv_noveldetail_description", "itv_click_num$delegate", "getItv_click_num", "itv_click_num", "itv_noveldetail_favorite$delegate", "getItv_noveldetail_favorite", "itv_noveldetail_favorite", "iv_detail_novel_audio$delegate", "getIv_detail_novel_audio", "iv_detail_novel_audio", "ll_like_noveldetail$delegate", "getLl_like_noveldetail", "ll_like_noveldetail", "Landroidx/recyclerview/widget/RecyclerView;", "rv_tag$delegate", "getRv_tag", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_tag", "Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "mCommentFragment", "Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "getMCommentFragment", "()Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "setMCommentFragment", "(Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;)V", "tv_noveldetail_chaptercount$delegate", "getTv_noveldetail_chaptercount", "tv_noveldetail_chaptercount", "itv_confirm_post$delegate", "getItv_confirm_post", "itv_confirm_post", "itv_favorite$delegate", "getItv_favorite", "itv_favorite", "tv_noveldetailbottom_favorite$delegate", "getTv_noveldetailbottom_favorite", "tv_noveldetailbottom_favorite", "", "mId", "Ljava/lang/String;", "tv_titleRight$delegate", "getTv_titleRight", "tv_titleRight", "ll_noveldetailbottom_favorite$delegate", "getLl_noveldetailbottom_favorite", "ll_noveldetailbottom_favorite", "mNovelId$delegate", "getMNovelId", "()Ljava/lang/String;", "mNovelId", "tv_click_favorite$delegate", "getTv_click_favorite", "tv_click_favorite", "ll_noveldetailbottom_startview$delegate", "getLl_noveldetailbottom_startview", "ll_noveldetailbottom_startview", "ll_noveldetailbottom_comment_input$delegate", "getLl_noveldetailbottom_comment_input", "ll_noveldetailbottom_comment_input", "Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_noveldetail$delegate", "getTablayout_noveldetail", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_noveldetail", "<init>", "Companion", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "Lkotlin/collections/ArrayList;", "fragments", "tabEntities", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "tabAdapter", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NovelDetailActivity extends MyThemeActivity<ComicsViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: ID */
    @NotNull
    private static String f10116ID = "id";
    public CommentFragment mCommentFragment;

    @Nullable
    private String mId;
    public NovelDetailInfoFragment mNovelDetailInfoFragment;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(ComicsViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$special$$inlined$viewModels$default$1
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

    /* renamed from: mNovelId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mNovelId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$mNovelId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return NovelDetailActivity.this.getIntent().getStringExtra(NovelDetailActivity.INSTANCE.getID());
        }
    });

    /* renamed from: btn_titleBack$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_titleBack = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$btn_titleBack$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) NovelDetailActivity.this.findViewById(R.id.btn_titleBack);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: tv_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelDetailActivity.this.findViewById(R.id.tv_titleRight);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: itv_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_favorite = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$itv_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) NovelDetailActivity.this.findViewById(R.id.itv_favorite);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_confirm_post$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_confirm_post = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$itv_confirm_post$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) NovelDetailActivity.this.findViewById(R.id.itv_confirm_post);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: ed_input_comment_novel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ed_input_comment_novel = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$ed_input_comment_novel$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatEditText invoke() {
            AppCompatEditText appCompatEditText = (AppCompatEditText) NovelDetailActivity.this.findViewById(R.id.ed_input_comment_novel);
            Intrinsics.checkNotNull(appCompatEditText);
            return appCompatEditText;
        }
    });

    /* renamed from: tv_click_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_click_favorite = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_click_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelDetailActivity.this.findViewById(R.id.tv_click_favorite);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_read_start$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_read_start = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_read_start$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelDetailActivity.this.findViewById(R.id.tv_read_start);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: iv_noveldetail_img$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_noveldetail_img = LazyKt__LazyJVMKt.lazy(new Function0<ShapeableImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$iv_noveldetail_img$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ShapeableImageView invoke() {
            ShapeableImageView shapeableImageView = (ShapeableImageView) NovelDetailActivity.this.findViewById(R.id.iv_noveldetail_img);
            Intrinsics.checkNotNull(shapeableImageView);
            return shapeableImageView;
        }
    });

    /* renamed from: iv_noveldetail_top$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_noveldetail_top = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$iv_noveldetail_top$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) NovelDetailActivity.this.findViewById(R.id.iv_noveldetail_top);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_noveldetail_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_noveldetail_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_noveldetail_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelDetailActivity.this.findViewById(R.id.tv_noveldetail_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_noveldetail_chaptercount$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_noveldetail_chaptercount = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_noveldetail_chaptercount$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelDetailActivity.this.findViewById(R.id.tv_noveldetail_chaptercount);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_noveldetail_category$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_noveldetail_category = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_noveldetail_category$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelDetailActivity.this.findViewById(R.id.tv_noveldetail_category);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_noveldetail_description$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_noveldetail_description = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_noveldetail_description$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelDetailActivity.this.findViewById(R.id.tv_noveldetail_description);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: itv_click_num$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_click_num = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$itv_click_num$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) NovelDetailActivity.this.findViewById(R.id.itv_click_num);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_noveldetail_like$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_noveldetail_like = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$itv_noveldetail_like$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) NovelDetailActivity.this.findViewById(R.id.itv_noveldetail_like);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_noveldetail_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_noveldetail_favorite = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$itv_noveldetail_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) NovelDetailActivity.this.findViewById(R.id.itv_noveldetail_favorite);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_noveldetial_commentnum$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_noveldetial_commentnum = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$itv_noveldetial_commentnum$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) NovelDetailActivity.this.findViewById(R.id.itv_noveldetial_commentnum);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: iv_detail_novel_audio$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_detail_novel_audio = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$iv_detail_novel_audio$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) NovelDetailActivity.this.findViewById(R.id.iv_detail_novel_audio);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_noveldetailbottom_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_noveldetailbottom_favorite = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_noveldetailbottom_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelDetailActivity.this.findViewById(R.id.tv_noveldetailbottom_favorite);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_noveldetail_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_noveldetail_favorite = LazyKt__LazyJVMKt.lazy(new Function0<FollowTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tv_noveldetail_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FollowTextView invoke() {
            FollowTextView followTextView = (FollowTextView) NovelDetailActivity.this.findViewById(R.id.tv_noveldetail_favorite);
            Intrinsics.checkNotNull(followTextView);
            return followTextView;
        }
    });

    /* renamed from: ll_noveldetailbottom_startview$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_noveldetailbottom_startview = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$ll_noveldetailbottom_startview$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) NovelDetailActivity.this.findViewById(R.id.ll_noveldetailbottom_startview);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_noveldetailbottom_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_noveldetailbottom_favorite = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$ll_noveldetailbottom_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) NovelDetailActivity.this.findViewById(R.id.ll_noveldetailbottom_favorite);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_like_noveldetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_like_noveldetail = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$ll_like_noveldetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) NovelDetailActivity.this.findViewById(R.id.ll_like_noveldetail);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tagAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tagAdapter = LazyKt__LazyJVMKt.lazy(new NovelDetailActivity$tagAdapter$2(this));

    /* renamed from: rv_tag$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_tag = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$rv_tag$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) NovelDetailActivity.this.findViewById(R.id.rv_tag);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: vp_noveldetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_noveldetail = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$vp_noveldetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) NovelDetailActivity.this.findViewById(R.id.vp_noveldetail);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: ll_noveldetail_bottom$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_noveldetail_bottom = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$ll_noveldetail_bottom$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) NovelDetailActivity.this.findViewById(R.id.ll_noveldetail_bottom);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_noveldetailbottom_comment_input$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_noveldetailbottom_comment_input = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$ll_noveldetailbottom_comment_input$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) NovelDetailActivity.this.findViewById(R.id.ll_noveldetailbottom_comment_input);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tablayout_noveldetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tablayout_noveldetail = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tablayout_noveldetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) NovelDetailActivity.this.findViewById(R.id.tablayout_noveldetail);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\t\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000e¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailActivity$Companion;", "", "Landroid/content/Context;", "context", "", "mId", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "ID", "Ljava/lang/String;", "getID", "()Ljava/lang/String;", "setID", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getID() {
            return NovelDetailActivity.f10116ID;
        }

        public final void setID(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            NovelDetailActivity.f10116ID = str;
        }

        public final void start(@NotNull Context context, @NotNull String mId) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(mId, "mId");
            Activity activity = (Activity) context;
            String localClassName = activity.getLocalClassName();
            Intrinsics.checkNotNullExpressionValue(localClassName, "activity.localClassName");
            if (StringsKt__StringsJVMKt.endsWith$default(localClassName, "NovelDetailActivity", false, 2, null)) {
                activity.finish();
            }
            Intent intent = new Intent(context, (Class<?>) NovelDetailActivity.class);
            intent.putExtra(NovelDetailActivity.INSTANCE.getID(), mId);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-4$lambda-2, reason: not valid java name */
    public static final void m5917bindEvent$lambda4$lambda2(final NovelDetailActivity this$0, final ComicsViewModel this_run, NovelDetailInfoBean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this$0.getTv_click_favorite().setText(C0843e0.m182a(it.click) + "人气 | " + ((Object) it.comment) + "人收藏");
        C2852c m2467d2 = C2354n.m2467d2(this$0);
        String str = it.img;
        if (str == null) {
            str = "";
        }
        C1558h mo770c = m2467d2.mo770c();
        mo770c.mo763X(str);
        ((C2851b) mo770c).m3292f0().m757R(this$0.getIv_noveldetail_img());
        C2852c m2467d22 = C2354n.m2467d2(this$0);
        String str2 = it.img;
        if (str2 == null) {
            str2 = "";
        }
        C1558h mo770c2 = m2467d22.mo770c();
        mo770c2.mo763X(str2);
        ((C2851b) mo770c2).m3292f0().m757R(this$0.getIv_noveldetail_top());
        if (it.ico.equals("audio")) {
            this$0.getTv_read_start().setText("开始播放");
        } else {
            this$0.getTv_read_start().setText("开始阅读");
        }
        this$0.getTv_noveldetail_name().setText(it.name);
        String str3 = it.chapter_count;
        Intrinsics.checkNotNullExpressionValue(str3, "it.chapter_count");
        if (str3.length() > 0) {
            this$0.getTv_noveldetail_chaptercount().setVisibility(0);
            TextView tv_noveldetail_chaptercount = this$0.getTv_noveldetail_chaptercount();
            StringBuilder m584F = C1499a.m584F((char) 20849);
            m584F.append((Object) it.chapter_count);
            m584F.append((char) 35805);
            tv_noveldetail_chaptercount.setText(m584F.toString());
        }
        String str4 = it.category;
        Intrinsics.checkNotNullExpressionValue(str4, "it.category");
        if (str4.length() > 0) {
            this$0.getTv_noveldetail_category().setVisibility(0);
            if (it.type.equals("novel")) {
                this$0.getTv_noveldetail_category().setText(it.category_name);
            } else {
                this$0.getTv_noveldetail_category().setText(it.category);
            }
        }
        List<Tags> list = it.tags;
        Intrinsics.checkNotNullExpressionValue(list, "it.tags");
        for (Tags tags : list) {
            if (tags.getName().equals(it.category.toString())) {
                Intrinsics.checkNotNullExpressionValue(tags.getId(), "item.id");
            }
        }
        C2354n.m2374A(this$0.getTv_noveldetail_category(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it2) {
                Intrinsics.checkNotNullParameter(it2, "it");
                HashMap hashMap = new HashMap();
                NovelDetailInfoBean value = ComicsViewModel.this.getNovelDetailInfo().getValue();
                hashMap.put("cat_id", String.valueOf(value == null ? null : value.category));
                ComicsModuleDetailActivity.Companion companion = ComicsModuleDetailActivity.INSTANCE;
                NovelDetailActivity novelDetailActivity = this$0;
                String obj = novelDetailActivity.getTv_noveldetail_category().getText().toString();
                String m2853g = new C2480j().m2853g(hashMap);
                Intrinsics.checkNotNullExpressionValue(m2853g, "Gson().toJson(mapsFilter)");
                companion.start(novelDetailActivity, obj, m2853g, "novel");
            }
        }, 1);
        this$0.getTv_noveldetail_description().setText(it.description);
        if (it.description.equals("")) {
            this$0.getTv_noveldetail_description().setVisibility(8);
        } else {
            this$0.getTv_noveldetail_description().setVisibility(0);
        }
        this$0.getItv_click_num().setText(C0843e0.m182a(it.click));
        this$0.getItv_noveldetail_like().setText(C0843e0.m182a(it.favorite));
        this$0.getItv_noveldetail_favorite().setText(Intrinsics.stringPlus(C0843e0.m182a(it.favorite), "人收藏"));
        this$0.getItv_noveldetial_commentnum().setText(it.comment);
        this$0.getIv_detail_novel_audio().setVisibility(it.ico.equals("audio") ? 0 : 8);
        Intrinsics.checkNotNullExpressionValue(it, "it");
        this$0.initView(it);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-4$lambda-3, reason: not valid java name */
    public static final void m5918bindEvent$lambda4$lambda3(NovelDetailActivity this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ImageTextView itv_noveldetail_like = this$0.getItv_noveldetail_like();
        Intrinsics.checkNotNullExpressionValue(it, "it");
        itv_noveldetail_like.setSelected(it.booleanValue());
        this$0.getItv_noveldetail_favorite().setSelected(it.booleanValue());
        this$0.getTv_noveldetailbottom_favorite().setSelected(it.booleanValue());
        if (it.booleanValue()) {
            this$0.getTv_noveldetailbottom_favorite().setText("已收藏");
        } else {
            this$0.getTv_noveldetailbottom_favorite().setText("收藏");
        }
        this$0.getTv_noveldetail_favorite().setSelected(it.booleanValue());
        if (it.booleanValue()) {
            this$0.getTv_noveldetail_favorite().setText("已收藏");
        } else {
            this$0.getTv_noveldetail_favorite().setText("+收藏");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMNovelId() {
        return (String) this.mNovelId.getValue();
    }

    private final NovelDetailActivity$tagAdapter$2.C38361 getTagAdapter() {
        return (NovelDetailActivity$tagAdapter$2.C38361) this.tagAdapter.getValue();
    }

    private final void initView(final NovelDetailInfoBean mNovelDetailInfoBean) {
        RecyclerView rv_tag = getRv_tag();
        NovelDetailActivity$tagAdapter$2.C38361 tagAdapter = getTagAdapter();
        List<Tags> list = mNovelDetailInfoBean.tags;
        Intrinsics.checkNotNullExpressionValue(list, "mNovelDetailInfoBean.tags");
        tagAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) list));
        rv_tag.setAdapter(getTagAdapter());
        FlexboxLayoutManager flexboxLayoutManager = new FlexboxLayoutManager(rv_tag.getContext());
        flexboxLayoutManager.m4176y(1);
        flexboxLayoutManager.m4175x(0);
        Unit unit = Unit.INSTANCE;
        rv_tag.setLayoutManager(flexboxLayoutManager);
        if (rv_tag.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_tag.getContext());
            c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_tag, 1.0d);
            c4053a.f10337e = C2354n.m2437V(rv_tag.getContext(), 1.0d);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            C1499a.m604Z(c4053a, rv_tag);
        }
        setMNovelDetailInfoFragment(NovelDetailInfoFragment.INSTANCE.newInstance(mNovelDetailInfoBean));
        CommentFragment.Companion companion = CommentFragment.INSTANCE;
        String str = mNovelDetailInfoBean.f10028id;
        Intrinsics.checkNotNullExpressionValue(str, "mNovelDetailInfoBean.id");
        setMCommentFragment(companion.newInstance(str, "novel"));
        final Lazy lazy = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MyThemeFragment<? extends Object>>>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$initView$fragments$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ArrayList<MyThemeFragment<? extends Object>> invoke() {
                return CollectionsKt__CollectionsKt.arrayListOf(NovelDetailActivity.this.getMNovelDetailInfoFragment(), NovelDetailActivity.this.getMCommentFragment());
            }
        });
        Lazy lazy2 = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<String>>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$initView$tabEntities$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ArrayList<String> invoke() {
                StringBuilder m586H = C1499a.m586H("评论(");
                m586H.append((Object) NovelDetailInfoBean.this.comment);
                m586H.append(')');
                return CollectionsKt__CollectionsKt.arrayListOf("作品详情", m586H.toString());
            }
        });
        Lazy lazy3 = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$initView$tabAdapter$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewPagerAdapter invoke() {
                ArrayList m5919initView$lambda7;
                FragmentManager supportFragmentManager = NovelDetailActivity.this.getSupportFragmentManager();
                Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
                m5919initView$lambda7 = NovelDetailActivity.m5919initView$lambda7(lazy);
                return new ViewPagerAdapter(supportFragmentManager, m5919initView$lambda7, 0, 4, null);
            }
        });
        ViewPager vp_noveldetail = getVp_noveldetail();
        vp_noveldetail.setOffscreenPageLimit(m5920initView$lambda8(lazy2).size());
        vp_noveldetail.setAdapter(m5921initView$lambda9(lazy3));
        vp_noveldetail.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$initView$2$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                if (position == 1) {
                    NovelDetailActivity.this.getLl_noveldetail_bottom().setVisibility(8);
                    NovelDetailActivity.this.getLl_noveldetailbottom_comment_input().setVisibility(0);
                } else {
                    NovelDetailActivity.this.getLl_noveldetail_bottom().setVisibility(0);
                    NovelDetailActivity.this.getLl_noveldetailbottom_comment_input().setVisibility(8);
                }
            }
        });
        SlidingTabLayout tablayout_noveldetail = getTablayout_noveldetail();
        ViewPager vp_noveldetail2 = getVp_noveldetail();
        Object[] array = m5920initView$lambda8(lazy2).toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tablayout_noveldetail.m4011e(vp_noveldetail2, (String[]) array);
        if (!m5920initView$lambda8(lazy2).isEmpty()) {
            getVp_noveldetail().setCurrentItem(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initView$lambda-7, reason: not valid java name */
    public static final ArrayList<MyThemeFragment<? extends Object>> m5919initView$lambda7(Lazy<? extends ArrayList<MyThemeFragment<? extends Object>>> lazy) {
        return lazy.getValue();
    }

    /* renamed from: initView$lambda-8, reason: not valid java name */
    private static final ArrayList<String> m5920initView$lambda8(Lazy<? extends ArrayList<String>> lazy) {
        return lazy.getValue();
    }

    /* renamed from: initView$lambda-9, reason: not valid java name */
    private static final ViewPagerAdapter m5921initView$lambda9(Lazy<ViewPagerAdapter> lazy) {
        return lazy.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        C2354n.m2374A(getBtn_titleBack(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$1
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
                NovelDetailActivity.this.onBackPressed();
            }
        }, 1);
        C2354n.m2374A(getTv_titleRight(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$2
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
                InviteActivity.INSTANCE.start(NovelDetailActivity.this);
            }
        }, 1);
        getItv_favorite().setVisibility(8);
        C2354n.m2374A(getItv_confirm_post(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                String valueOf = String.valueOf(NovelDetailActivity.this.getEd_input_comment_novel().getText());
                if (valueOf.length() == 0) {
                    C2354n.m2449Z("请输入评论内容");
                } else {
                    NovelDetailActivity.this.getMCommentFragment().sendCommentOut(valueOf);
                    NovelDetailActivity.this.getEd_input_comment_novel().setText("");
                }
            }
        }, 1);
        String mNovelId = getMNovelId();
        if (mNovelId != null) {
            ComicsViewModel.novelDetail$default(getViewModel(), mNovelId, false, 2, null);
        }
        final ComicsViewModel viewModel = getViewModel();
        viewModel.getNovelDetailInfo().observe(this, new Observer() { // from class: b.a.a.a.t.j.l
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                NovelDetailActivity.m5917bindEvent$lambda4$lambda2(NovelDetailActivity.this, viewModel, (NovelDetailInfoBean) obj);
            }
        });
        viewModel.getMHasLike().observe(this, new Observer() { // from class: b.a.a.a.t.j.m
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                NovelDetailActivity.m5918bindEvent$lambda4$lambda3(NovelDetailActivity.this, (Boolean) obj);
            }
        });
        C2354n.m2374A(getTv_noveldetail_favorite(), 0L, new Function1<FollowTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FollowTextView followTextView) {
                invoke2(followTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull FollowTextView it) {
                String mNovelId2;
                Intrinsics.checkNotNullParameter(it, "it");
                mNovelId2 = NovelDetailActivity.this.getMNovelId();
                if (mNovelId2 == null) {
                    return;
                }
                final NovelDetailActivity novelDetailActivity = NovelDetailActivity.this;
                novelDetailActivity.getViewModel().novelDoFavorite(mNovelId2, false, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$3$1$1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                        NovelDetailActivity.this.getViewModel().updateLikeNumNovel(!NovelDetailActivity.this.getTv_noveldetail_favorite().isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$3$1$2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
        C2354n.m2374A(getLl_noveldetailbottom_startview(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                String str;
                Intrinsics.checkNotNullParameter(it, "it");
                NovelDetailInfoBean value = ComicsViewModel.this.getNovelDetailInfo().getValue();
                if (StringsKt__StringsJVMKt.equals$default(value == null ? null : value.ico, "audio", false, 2, null)) {
                    NovelDetailInfoBean value2 = ComicsViewModel.this.getNovelDetailInfo().getValue();
                    if (value2 == null) {
                        return;
                    }
                    ComicsViewModel comicsViewModel = ComicsViewModel.this;
                    NovelDetailActivity novelDetailActivity = this;
                    NovelDetailInfoBean value3 = comicsViewModel.getNovelDetailInfo().getValue();
                    if (value3 == null || (str = value3.last_chapter_id) == null) {
                        return;
                    }
                    AudioPlayerActivity.INSTANCE.start(novelDetailActivity, str, value2);
                    return;
                }
                NovelDetailInfoBean value4 = ComicsViewModel.this.getNovelDetailInfo().getValue();
                if (value4 == null) {
                    return;
                }
                NovelDetailActivity novelDetailActivity2 = this;
                ComicsViewModel comicsViewModel2 = ComicsViewModel.this;
                NovelChapterViewActivity.Companion companion = NovelChapterViewActivity.INSTANCE;
                NovelDetailInfoBean value5 = comicsViewModel2.getNovelDetailInfo().getValue();
                Intrinsics.checkNotNull(value5);
                String str2 = value5.last_chapter_id;
                Intrinsics.checkNotNullExpressionValue(str2, "novelDetailInfo.value!!.last_chapter_id");
                companion.start(novelDetailActivity2, str2, value4);
            }
        }, 1);
        C2354n.m2374A(getLl_noveldetailbottom_favorite(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$5
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
                String mNovelId2;
                Intrinsics.checkNotNullParameter(it, "it");
                mNovelId2 = NovelDetailActivity.this.getMNovelId();
                if (mNovelId2 == null) {
                    return;
                }
                final NovelDetailActivity novelDetailActivity = NovelDetailActivity.this;
                novelDetailActivity.getViewModel().novelDoFavorite(mNovelId2, false, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$5$1$1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                        NovelDetailActivity.this.getViewModel().updateLikeNumNovel(!NovelDetailActivity.this.getItv_noveldetail_like().isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$5$1$2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
        C2354n.m2374A(getLl_like_noveldetail(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$6
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                String str;
                Intrinsics.checkNotNullParameter(it, "it");
                NovelDetailInfoBean value = ComicsViewModel.this.getNovelDetailInfo().getValue();
                if (value == null || (str = value.f10028id) == null) {
                    return;
                }
                final NovelDetailActivity novelDetailActivity = this;
                novelDetailActivity.getViewModel().novelDoFavorite(str, false, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$6$1$1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                        NovelDetailActivity.this.getViewModel().updateLikeNumNovel(!NovelDetailActivity.this.getItv_noveldetail_like().isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$bindEvent$5$6$1$2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
    }

    @NotNull
    public final RelativeLayout getBtn_titleBack() {
        return (RelativeLayout) this.btn_titleBack.getValue();
    }

    @NotNull
    public final AppCompatEditText getEd_input_comment_novel() {
        return (AppCompatEditText) this.ed_input_comment_novel.getValue();
    }

    @NotNull
    public final ImageTextView getItv_click_num() {
        return (ImageTextView) this.itv_click_num.getValue();
    }

    @NotNull
    public final ImageTextView getItv_confirm_post() {
        return (ImageTextView) this.itv_confirm_post.getValue();
    }

    @NotNull
    public final ImageTextView getItv_favorite() {
        return (ImageTextView) this.itv_favorite.getValue();
    }

    @NotNull
    public final ImageTextView getItv_noveldetail_favorite() {
        return (ImageTextView) this.itv_noveldetail_favorite.getValue();
    }

    @NotNull
    public final ImageTextView getItv_noveldetail_like() {
        return (ImageTextView) this.itv_noveldetail_like.getValue();
    }

    @NotNull
    public final ImageTextView getItv_noveldetial_commentnum() {
        return (ImageTextView) this.itv_noveldetial_commentnum.getValue();
    }

    @NotNull
    public final ImageView getIv_detail_novel_audio() {
        return (ImageView) this.iv_detail_novel_audio.getValue();
    }

    @NotNull
    public final ShapeableImageView getIv_noveldetail_img() {
        return (ShapeableImageView) this.iv_noveldetail_img.getValue();
    }

    @NotNull
    public final ImageView getIv_noveldetail_top() {
        return (ImageView) this.iv_noveldetail_top.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_detail_novel;
    }

    @NotNull
    public final LinearLayout getLl_like_noveldetail() {
        return (LinearLayout) this.ll_like_noveldetail.getValue();
    }

    @NotNull
    public final LinearLayout getLl_noveldetail_bottom() {
        return (LinearLayout) this.ll_noveldetail_bottom.getValue();
    }

    @NotNull
    public final LinearLayout getLl_noveldetailbottom_comment_input() {
        return (LinearLayout) this.ll_noveldetailbottom_comment_input.getValue();
    }

    @NotNull
    public final LinearLayout getLl_noveldetailbottom_favorite() {
        return (LinearLayout) this.ll_noveldetailbottom_favorite.getValue();
    }

    @NotNull
    public final LinearLayout getLl_noveldetailbottom_startview() {
        return (LinearLayout) this.ll_noveldetailbottom_startview.getValue();
    }

    @NotNull
    public final CommentFragment getMCommentFragment() {
        CommentFragment commentFragment = this.mCommentFragment;
        if (commentFragment != null) {
            return commentFragment;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mCommentFragment");
        throw null;
    }

    @NotNull
    public final NovelDetailInfoFragment getMNovelDetailInfoFragment() {
        NovelDetailInfoFragment novelDetailInfoFragment = this.mNovelDetailInfoFragment;
        if (novelDetailInfoFragment != null) {
            return novelDetailInfoFragment;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mNovelDetailInfoFragment");
        throw null;
    }

    @NotNull
    public final RecyclerView getRv_tag() {
        return (RecyclerView) this.rv_tag.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTablayout_noveldetail() {
        return (SlidingTabLayout) this.tablayout_noveldetail.getValue();
    }

    @NotNull
    public final TextView getTv_click_favorite() {
        return (TextView) this.tv_click_favorite.getValue();
    }

    @NotNull
    public final TextView getTv_noveldetail_category() {
        return (TextView) this.tv_noveldetail_category.getValue();
    }

    @NotNull
    public final TextView getTv_noveldetail_chaptercount() {
        return (TextView) this.tv_noveldetail_chaptercount.getValue();
    }

    @NotNull
    public final TextView getTv_noveldetail_description() {
        return (TextView) this.tv_noveldetail_description.getValue();
    }

    @NotNull
    public final FollowTextView getTv_noveldetail_favorite() {
        return (FollowTextView) this.tv_noveldetail_favorite.getValue();
    }

    @NotNull
    public final TextView getTv_noveldetail_name() {
        return (TextView) this.tv_noveldetail_name.getValue();
    }

    @NotNull
    public final TextView getTv_noveldetailbottom_favorite() {
        return (TextView) this.tv_noveldetailbottom_favorite.getValue();
    }

    @NotNull
    public final TextView getTv_read_start() {
        return (TextView) this.tv_read_start.getValue();
    }

    @NotNull
    public final TextView getTv_titleRight() {
        return (TextView) this.tv_titleRight.getValue();
    }

    @NotNull
    public final ComicsViewModel getViewModel() {
        return (ComicsViewModel) this.viewModel.getValue();
    }

    @NotNull
    public final ViewPager getVp_noveldetail() {
        return (ViewPager) this.vp_noveldetail.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        String stringExtra = getIntent().getStringExtra(f10116ID);
        this.mId = stringExtra;
        if (stringExtra == null || stringExtra.length() == 0) {
            onBackPressed();
        }
        super.onCreate(savedInstanceState);
        ImmersionBar.with(this).fitsSystemWindows(true).statusBarColorInt(getResources().getColor(R.color.black)).statusBarDarkFont(true).init();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
    }

    public final void setMCommentFragment(@NotNull CommentFragment commentFragment) {
        Intrinsics.checkNotNullParameter(commentFragment, "<set-?>");
        this.mCommentFragment = commentFragment;
    }

    public final void setMNovelDetailInfoFragment(@NotNull NovelDetailInfoFragment novelDetailInfoFragment) {
        Intrinsics.checkNotNullParameter(novelDetailInfoFragment, "<set-?>");
        this.mNovelDetailInfoFragment = novelDetailInfoFragment;
    }

    @NotNull
    public final ComicsViewModel viewModelInstance() {
        return getViewModel();
    }
}
