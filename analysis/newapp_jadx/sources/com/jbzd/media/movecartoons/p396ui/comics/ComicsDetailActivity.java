package com.jbzd.media.movecartoons.p396ui.comics;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
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
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.Tags;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailActivity;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailActivity$tagAdapter$2;
import com.jbzd.media.movecartoons.p396ui.comics.CommentFragment;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p258c.C2480j;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Á\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002*\u0001%\u0018\u0000 \u0086\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u0086\u0001B\b¢\u0006\u0005\b\u0085\u0001\u0010\u000eJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\r\u0010\b\u001a\u00020\u0002¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u0019\u0010\u0011\u001a\u00020\u00052\b\u0010\u0010\u001a\u0004\u0018\u00010\u000fH\u0014¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0005H\u0014¢\u0006\u0004\b\u0013\u0010\u000eR\u001d\u0010\u0019\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001c\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u0016\u001a\u0004\b\u001b\u0010\u0018R\u001d\u0010!\u001a\u00020\u001d8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u0016\u001a\u0004\b\u001f\u0010 R\u001d\u0010$\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u0016\u001a\u0004\b#\u0010\u0018R\u001d\u0010)\u001a\u00020%8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u0016\u001a\u0004\b'\u0010(R\u001d\u0010.\u001a\u00020*8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u0016\u001a\u0004\b,\u0010-R\u001d\u00103\u001a\u00020/8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u0016\u001a\u0004\b1\u00102R\u001d\u00106\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u0016\u001a\u0004\b5\u0010\u0018R\u001d\u0010;\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b8\u0010\u0016\u001a\u0004\b9\u0010:R\u001d\u0010@\u001a\u00020<8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b=\u0010\u0016\u001a\u0004\b>\u0010?R\u001d\u0010C\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bA\u0010\u0016\u001a\u0004\bB\u0010\u0018R\u001d\u0010F\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bD\u0010\u0016\u001a\u0004\bE\u0010\u0018R\u001d\u0010I\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bG\u0010\u0016\u001a\u0004\bH\u0010\tR\u001d\u0010N\u001a\u00020J8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bK\u0010\u0016\u001a\u0004\bL\u0010MR\u001d\u0010S\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bP\u0010\u0016\u001a\u0004\bQ\u0010RR\u001d\u0010V\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bT\u0010\u0016\u001a\u0004\bU\u0010:R\u001d\u0010[\u001a\u00020W8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bX\u0010\u0016\u001a\u0004\bY\u0010ZR\"\u0010]\u001a\u00020\\8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b]\u0010^\u001a\u0004\b_\u0010`\"\u0004\ba\u0010bR\u001d\u0010g\u001a\u00020c8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bd\u0010\u0016\u001a\u0004\be\u0010fR\u001d\u0010j\u001a\u00020*8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bh\u0010\u0016\u001a\u0004\bi\u0010-R\u001d\u0010o\u001a\u00020k8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bl\u0010\u0016\u001a\u0004\bm\u0010nR\"\u0010q\u001a\u00020p8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bq\u0010r\u001a\u0004\bs\u0010t\"\u0004\bu\u0010vR\u001d\u0010y\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bw\u0010\u0016\u001a\u0004\bx\u0010\u0018R\u001d\u0010|\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bz\u0010\u0016\u001a\u0004\b{\u0010:R\u001d\u0010\u007f\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b}\u0010\u0016\u001a\u0004\b~\u0010:R\"\u0010\u0084\u0001\u001a\u00030\u0080\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0081\u0001\u0010\u0016\u001a\u0006\b\u0082\u0001\u0010\u0083\u0001¨\u0006\u0090\u0001²\u00069\u0010\u008b\u0001\u001a,\u0012\u0010\u0012\u000e\u0012\t\b\u0001\u0012\u0005\u0018\u00010\u0089\u00010\u0088\u00010\u0087\u0001j\u0015\u0012\u0010\u0012\u000e\u0012\t\b\u0001\u0012\u0005\u0018\u00010\u0089\u00010\u0088\u0001`\u008a\u00018\n@\nX\u008a\u0084\u0002²\u0006#\u0010\u008d\u0001\u001a\u0016\u0012\u0005\u0012\u00030\u008c\u00010\u0087\u0001j\n\u0012\u0005\u0012\u00030\u008c\u0001`\u008a\u00018\n@\nX\u008a\u0084\u0002²\u0006\u0010\u0010\u008f\u0001\u001a\u00030\u008e\u00018\n@\nX\u008a\u0084\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "mComicsDetail", "", "initView", "(Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;)V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "", "getLayoutId", "()I", "bindEvent", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "onDestroy", "Landroid/widget/TextView;", "tv_comicsdetail_chaptercount$delegate", "Lkotlin/Lazy;", "getTv_comicsdetail_chaptercount", "()Landroid/widget/TextView;", "tv_comicsdetail_chaptercount", "tv_click_favorite$delegate", "getTv_click_favorite", "tv_click_favorite", "Landroidx/viewpager/widget/ViewPager;", "vp_comicsdetail$delegate", "getVp_comicsdetail", "()Landroidx/viewpager/widget/ViewPager;", "vp_comicsdetail", "tv_titleRight$delegate", "getTv_titleRight", "tv_titleRight", "com/jbzd/media/movecartoons/ui/comics/ComicsDetailActivity$tagAdapter$2$1", "tagAdapter$delegate", "getTagAdapter", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailActivity$tagAdapter$2$1;", "tagAdapter", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_confirm_post$delegate", "getItv_confirm_post", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_confirm_post", "Landroidx/appcompat/widget/AppCompatEditText;", "ed_input_comment_comics$delegate", "getEd_input_comment_comics", "()Landroidx/appcompat/widget/AppCompatEditText;", "ed_input_comment_comics", "tv_comicsdetail_category$delegate", "getTv_comicsdetail_category", "tv_comicsdetail_category", "Landroid/widget/LinearLayout;", "ll_comicsdetailbottom_comment_input$delegate", "getLl_comicsdetailbottom_comment_input", "()Landroid/widget/LinearLayout;", "ll_comicsdetailbottom_comment_input", "Landroidx/recyclerview/widget/RecyclerView;", "rv_tag$delegate", "getRv_tag", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_tag", "tv_comicsdetail_name$delegate", "getTv_comicsdetail_name", "tv_comicsdetail_name", "tv_comicsdetailbottom_favorite$delegate", "getTv_comicsdetailbottom_favorite", "tv_comicsdetailbottom_favorite", "viewModel$delegate", "getViewModel", "viewModel", "Lcom/google/android/material/imageview/ShapeableImageView;", "iv_comicsdetail_img$delegate", "getIv_comicsdetail_img", "()Lcom/google/android/material/imageview/ShapeableImageView;", "iv_comicsdetail_img", "Landroid/widget/ImageView;", "iv_comicsdetail_top$delegate", "getIv_comicsdetail_top", "()Landroid/widget/ImageView;", "iv_comicsdetail_top", "ll_comicsdetail_bottom$delegate", "getLl_comicsdetail_bottom", "ll_comicsdetail_bottom", "Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_comicsdetail$delegate", "getTablayout_comicsdetail", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_comicsdetail", "Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "mCommentFragment", "Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "getMCommentFragment", "()Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "setMCommentFragment", "(Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;)V", "Landroid/widget/RelativeLayout;", "btn_titleBack$delegate", "getBtn_titleBack", "()Landroid/widget/RelativeLayout;", "btn_titleBack", "itv_favorite$delegate", "getItv_favorite", "itv_favorite", "Lcom/jbzd/media/movecartoons/view/FollowTextView;", "tv_comicsdetail_favorite$delegate", "getTv_comicsdetail_favorite", "()Lcom/jbzd/media/movecartoons/view/FollowTextView;", "tv_comicsdetail_favorite", "Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment;", "mComicsDetailInfoFragment", "Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment;", "getMComicsDetailInfoFragment", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment;", "setMComicsDetailInfoFragment", "(Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment;)V", "tv_comicsdetail_description$delegate", "getTv_comicsdetail_description", "tv_comicsdetail_description", "ll_comicsdetailbottom_startview$delegate", "getLl_comicsdetailbottom_startview", "ll_comicsdetailbottom_startview", "ll_comicsdetailbottom_favorite$delegate", "getLl_comicsdetailbottom_favorite", "ll_comicsdetailbottom_favorite", "Landroid/view/View;", "ll_bottom_tool$delegate", "getLl_bottom_tool", "()Landroid/view/View;", "ll_bottom_tool", "<init>", "Companion", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "Lkotlin/collections/ArrayList;", "fragments", "", "tabEntities", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "tabAdapter", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsDetailActivity extends MyThemeActivity<ComicsViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String idComics = "";
    public ComicsDetailInfoFragment mComicsDetailInfoFragment;
    public CommentFragment mCommentFragment;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(ComicsViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$special$$inlined$viewModels$default$1
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

    /* renamed from: tv_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tv_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsDetailActivity.this.findViewById(R.id.tv_titleRight);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: btn_titleBack$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_titleBack = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$btn_titleBack$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) ComicsDetailActivity.this.findViewById(R.id.btn_titleBack);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: itv_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_favorite = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$itv_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) ComicsDetailActivity.this.findViewById(R.id.itv_favorite);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_confirm_post$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_confirm_post = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$itv_confirm_post$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) ComicsDetailActivity.this.findViewById(R.id.itv_confirm_post);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: ed_input_comment_comics$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ed_input_comment_comics = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$ed_input_comment_comics$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatEditText invoke() {
            AppCompatEditText appCompatEditText = (AppCompatEditText) ComicsDetailActivity.this.findViewById(R.id.ed_input_comment_comics);
            Intrinsics.checkNotNull(appCompatEditText);
            return appCompatEditText;
        }
    });

    /* renamed from: tv_comicsdetail_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_comicsdetail_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tv_comicsdetail_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsDetailActivity.this.findViewById(R.id.tv_comicsdetail_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_comicsdetail_chaptercount$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_comicsdetail_chaptercount = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tv_comicsdetail_chaptercount$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsDetailActivity.this.findViewById(R.id.tv_comicsdetail_chaptercount);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_comicsdetail_category$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_comicsdetail_category = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tv_comicsdetail_category$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsDetailActivity.this.findViewById(R.id.tv_comicsdetail_category);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_comicsdetail_description$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_comicsdetail_description = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tv_comicsdetail_description$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsDetailActivity.this.findViewById(R.id.tv_comicsdetail_description);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_click_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_click_favorite = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tv_click_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsDetailActivity.this.findViewById(R.id.tv_click_favorite);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: iv_comicsdetail_img$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_comicsdetail_img = LazyKt__LazyJVMKt.lazy(new Function0<ShapeableImageView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$iv_comicsdetail_img$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ShapeableImageView invoke() {
            ShapeableImageView shapeableImageView = (ShapeableImageView) ComicsDetailActivity.this.findViewById(R.id.iv_comicsdetail_img);
            Intrinsics.checkNotNull(shapeableImageView);
            return shapeableImageView;
        }
    });

    /* renamed from: iv_comicsdetail_top$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_comicsdetail_top = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$iv_comicsdetail_top$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) ComicsDetailActivity.this.findViewById(R.id.iv_comicsdetail_top);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_comicsdetailbottom_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_comicsdetailbottom_favorite = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tv_comicsdetailbottom_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsDetailActivity.this.findViewById(R.id.tv_comicsdetailbottom_favorite);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_comicsdetail_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_comicsdetail_favorite = LazyKt__LazyJVMKt.lazy(new Function0<FollowTextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tv_comicsdetail_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FollowTextView invoke() {
            FollowTextView followTextView = (FollowTextView) ComicsDetailActivity.this.findViewById(R.id.tv_comicsdetail_favorite);
            Intrinsics.checkNotNull(followTextView);
            return followTextView;
        }
    });

    /* renamed from: ll_comicsdetailbottom_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_comicsdetailbottom_favorite = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$ll_comicsdetailbottom_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) ComicsDetailActivity.this.findViewById(R.id.ll_comicsdetailbottom_favorite);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_comicsdetailbottom_startview$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_comicsdetailbottom_startview = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$ll_comicsdetailbottom_startview$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) ComicsDetailActivity.this.findViewById(R.id.ll_comicsdetailbottom_startview);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tagAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tagAdapter = LazyKt__LazyJVMKt.lazy(new ComicsDetailActivity$tagAdapter$2(this));

    /* renamed from: rv_tag$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_tag = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$rv_tag$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) ComicsDetailActivity.this.findViewById(R.id.rv_tag);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: vp_comicsdetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_comicsdetail = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$vp_comicsdetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) ComicsDetailActivity.this.findViewById(R.id.vp_comicsdetail);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: ll_comicsdetail_bottom$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_comicsdetail_bottom = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$ll_comicsdetail_bottom$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) ComicsDetailActivity.this.findViewById(R.id.ll_comicsdetail_bottom);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_bottom_tool$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_bottom_tool = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$ll_bottom_tool$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final View invoke() {
            View findViewById = ComicsDetailActivity.this.findViewById(R.id.ll_bottom_tool);
            Intrinsics.checkNotNull(findViewById);
            return findViewById;
        }
    });

    /* renamed from: ll_comicsdetailbottom_comment_input$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_comicsdetailbottom_comment_input = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$ll_comicsdetailbottom_comment_input$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) ComicsDetailActivity.this.findViewById(R.id.ll_comicsdetailbottom_comment_input);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tablayout_comicsdetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tablayout_comicsdetail = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$tablayout_comicsdetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) ComicsDetailActivity.this.findViewById(R.id.tablayout_comicsdetail);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\t\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000e¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailActivity$Companion;", "", "Landroid/content/Context;", "context", "", "comicsId", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "idComics", "Ljava/lang/String;", "getIdComics", "()Ljava/lang/String;", "setIdComics", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getIdComics() {
            return ComicsDetailActivity.idComics;
        }

        public final void setIdComics(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            ComicsDetailActivity.idComics = str;
        }

        public final void start(@NotNull Context context, @NotNull String comicsId) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(comicsId, "comicsId");
            setIdComics(comicsId);
            context.startActivity(new Intent(context, (Class<?>) ComicsDetailActivity.class));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-3$lambda-1, reason: not valid java name */
    public static final void m5753bindEvent$lambda3$lambda1(final ComicsDetailActivity this$0, ComicsDetailInfoBean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getTv_comicsdetail_name().setText(it.name);
        String str = it.chapter_count;
        Intrinsics.checkNotNullExpressionValue(str, "it.chapter_count");
        if (str.length() > 0) {
            this$0.getTv_comicsdetail_chaptercount().setVisibility(0);
            TextView tv_comicsdetail_chaptercount = this$0.getTv_comicsdetail_chaptercount();
            StringBuilder m584F = C1499a.m584F((char) 20849);
            m584F.append((Object) it.chapter_count);
            m584F.append((char) 35805);
            tv_comicsdetail_chaptercount.setText(m584F.toString());
        }
        String str2 = it.category;
        Intrinsics.checkNotNullExpressionValue(str2, "it.category");
        if (str2.length() > 0) {
            this$0.getTv_comicsdetail_category().setVisibility(0);
            this$0.getTv_comicsdetail_category().setText(it.category);
        }
        List<Tags> list = it.tags;
        Intrinsics.checkNotNullExpressionValue(list, "it.tags");
        for (Tags tags : list) {
            if (tags.getName().equals(it.category.toString())) {
                Intrinsics.checkNotNullExpressionValue(tags.getId(), "item.id");
            }
        }
        C2354n.m2374A(this$0.getTv_comicsdetail_category(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$4$1$2
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
                hashMap.put("cat_id", ComicsDetailActivity.this.getTv_comicsdetail_category().getText().toString());
                ComicsModuleDetailActivity.Companion companion = ComicsModuleDetailActivity.INSTANCE;
                ComicsDetailActivity comicsDetailActivity = ComicsDetailActivity.this;
                String obj = comicsDetailActivity.getTv_comicsdetail_category().getText().toString();
                String m2853g = new C2480j().m2853g(hashMap);
                Intrinsics.checkNotNullExpressionValue(m2853g, "Gson().toJson(mapsFilter)");
                companion.start(comicsDetailActivity, obj, m2853g, "");
            }
        }, 1);
        this$0.getTv_comicsdetail_description().setText(it.description);
        if (it.description.equals("")) {
            this$0.getTv_comicsdetail_description().setVisibility(8);
        } else {
            this$0.getTv_comicsdetail_description().setVisibility(0);
        }
        this$0.getTv_click_favorite().setText(C0843e0.m182a(it.click) + "人气 | " + ((Object) it.comment) + "人收藏");
        C2354n.m2467d2(this$0).m3298p(it.img).m3290d0().m757R(this$0.getIv_comicsdetail_img());
        C2354n.m2467d2(this$0).m3298p(it.img).m3290d0().m757R(this$0.getIv_comicsdetail_top());
        Intrinsics.checkNotNullExpressionValue(it, "it");
        this$0.initView(it);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-3$lambda-2, reason: not valid java name */
    public static final void m5754bindEvent$lambda3$lambda2(ComicsDetailActivity this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        TextView tv_comicsdetailbottom_favorite = this$0.getTv_comicsdetailbottom_favorite();
        Intrinsics.checkNotNullExpressionValue(it, "it");
        tv_comicsdetailbottom_favorite.setSelected(it.booleanValue());
        if (it.booleanValue()) {
            this$0.getTv_comicsdetailbottom_favorite().setText("已收藏");
        } else {
            this$0.getTv_comicsdetailbottom_favorite().setText("+收藏");
        }
        this$0.getTv_comicsdetail_favorite().setSelected(it.booleanValue());
        if (it.booleanValue()) {
            this$0.getTv_comicsdetail_favorite().setText("已收藏");
        } else {
            this$0.getTv_comicsdetail_favorite().setText("+收藏");
        }
    }

    private final ComicsDetailActivity$tagAdapter$2.C36681 getTagAdapter() {
        return (ComicsDetailActivity$tagAdapter$2.C36681) this.tagAdapter.getValue();
    }

    private final void initView(final ComicsDetailInfoBean mComicsDetail) {
        RecyclerView rv_tag = getRv_tag();
        ComicsDetailActivity$tagAdapter$2.C36681 tagAdapter = getTagAdapter();
        List<Tags> list = mComicsDetail.tags;
        Intrinsics.checkNotNullExpressionValue(list, "mComicsDetail.tags");
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
        setMComicsDetailInfoFragment(ComicsDetailInfoFragment.INSTANCE.newInstance(mComicsDetail));
        CommentFragment.Companion companion = CommentFragment.INSTANCE;
        String str = mComicsDetail.f10010id;
        Intrinsics.checkNotNullExpressionValue(str, "mComicsDetail.id");
        setMCommentFragment(companion.newInstance(str, "comics"));
        final Lazy lazy = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MyThemeFragment<? extends Object>>>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$initView$fragments$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ArrayList<MyThemeFragment<? extends Object>> invoke() {
                return CollectionsKt__CollectionsKt.arrayListOf(ComicsDetailActivity.this.getMComicsDetailInfoFragment(), ComicsDetailActivity.this.getMCommentFragment());
            }
        });
        Lazy lazy2 = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<String>>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$initView$tabEntities$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ArrayList<String> invoke() {
                StringBuilder m586H = C1499a.m586H("评论(");
                m586H.append((Object) ComicsDetailInfoBean.this.comment);
                m586H.append(')');
                return CollectionsKt__CollectionsKt.arrayListOf("漫画详情", m586H.toString());
            }
        });
        Lazy lazy3 = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$initView$tabAdapter$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewPagerAdapter invoke() {
                ArrayList m5755initView$lambda6;
                FragmentManager supportFragmentManager = ComicsDetailActivity.this.getSupportFragmentManager();
                Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
                m5755initView$lambda6 = ComicsDetailActivity.m5755initView$lambda6(lazy);
                return new ViewPagerAdapter(supportFragmentManager, m5755initView$lambda6, 0, 4, null);
            }
        });
        ViewPager vp_comicsdetail = getVp_comicsdetail();
        vp_comicsdetail.setOffscreenPageLimit(m5756initView$lambda7(lazy2).size());
        vp_comicsdetail.setAdapter(m5757initView$lambda8(lazy3));
        vp_comicsdetail.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$initView$2$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                ComicsDetailActivity.this.getLl_bottom_tool().setVisibility(8);
                if (position == 1) {
                    ComicsDetailActivity.this.getLl_comicsdetail_bottom().setVisibility(8);
                    ComicsDetailActivity.this.getLl_comicsdetailbottom_comment_input().setVisibility(0);
                } else {
                    ComicsDetailActivity.this.getLl_comicsdetail_bottom().setVisibility(0);
                    ComicsDetailActivity.this.getLl_comicsdetailbottom_comment_input().setVisibility(8);
                }
            }
        });
        SlidingTabLayout tablayout_comicsdetail = getTablayout_comicsdetail();
        ViewPager vp_comicsdetail2 = getVp_comicsdetail();
        Object[] array = m5756initView$lambda7(lazy2).toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tablayout_comicsdetail.m4011e(vp_comicsdetail2, (String[]) array);
        if (!m5756initView$lambda7(lazy2).isEmpty()) {
            getVp_comicsdetail().setCurrentItem(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initView$lambda-6, reason: not valid java name */
    public static final ArrayList<MyThemeFragment<? extends Object>> m5755initView$lambda6(Lazy<? extends ArrayList<MyThemeFragment<? extends Object>>> lazy) {
        return lazy.getValue();
    }

    /* renamed from: initView$lambda-7, reason: not valid java name */
    private static final ArrayList<String> m5756initView$lambda7(Lazy<? extends ArrayList<String>> lazy) {
        return lazy.getValue();
    }

    /* renamed from: initView$lambda-8, reason: not valid java name */
    private static final ViewPagerAdapter m5757initView$lambda8(Lazy<ViewPagerAdapter> lazy) {
        return lazy.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        C2354n.m2374A(getTv_titleRight(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$1
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
                InviteActivity.INSTANCE.start(ComicsDetailActivity.this);
            }
        }, 1);
        C2354n.m2374A(getBtn_titleBack(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$2
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
                ComicsDetailActivity.this.onBackPressed();
            }
        }, 1);
        getItv_favorite().setVisibility(8);
        C2354n.m2374A(getItv_confirm_post(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$3
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
                String valueOf = String.valueOf(ComicsDetailActivity.this.getEd_input_comment_comics().getText());
                if (valueOf.length() == 0) {
                    C2354n.m2449Z("请输入评论内容");
                } else {
                    ComicsDetailActivity.this.getMCommentFragment().sendCommentOut(valueOf);
                    ComicsDetailActivity.this.getEd_input_comment_comics().setText("");
                }
            }
        }, 1);
        ComicsViewModel.comicsDetail$default(getViewModel(), idComics, false, 2, null);
        final ComicsViewModel viewModel = getViewModel();
        viewModel.getComicsDetailInfo().observe(this, new Observer() { // from class: b.a.a.a.t.d.g
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ComicsDetailActivity.m5753bindEvent$lambda3$lambda1(ComicsDetailActivity.this, (ComicsDetailInfoBean) obj);
            }
        });
        viewModel.getMHasLike().observe(this, new Observer() { // from class: b.a.a.a.t.d.e
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ComicsDetailActivity.m5754bindEvent$lambda3$lambda2(ComicsDetailActivity.this, (Boolean) obj);
            }
        });
        C2354n.m2374A(getTv_comicsdetail_favorite(), 0L, new Function1<FollowTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$4$3
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
                Intrinsics.checkNotNullParameter(it, "it");
                ComicsViewModel viewModel2 = ComicsDetailActivity.this.getViewModel();
                String idComics2 = ComicsDetailActivity.INSTANCE.getIdComics();
                final ComicsDetailActivity comicsDetailActivity = ComicsDetailActivity.this;
                viewModel2.comicsDoFavorite(idComics2, false, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$4$3.1
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
                        ComicsDetailActivity.this.getViewModel().updateLikeNum(!ComicsDetailActivity.this.getTv_comicsdetail_favorite().isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$4$3.2
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
        C2354n.m2374A(getLl_comicsdetailbottom_favorite(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$4$4
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
                Intrinsics.checkNotNullParameter(it, "it");
                ComicsViewModel viewModel2 = ComicsDetailActivity.this.getViewModel();
                String idComics2 = ComicsDetailActivity.INSTANCE.getIdComics();
                final ComicsDetailActivity comicsDetailActivity = ComicsDetailActivity.this;
                viewModel2.comicsDoFavorite(idComics2, false, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$4$4.1
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
                        ComicsDetailActivity.this.getViewModel().updateLikeNum(!ComicsDetailActivity.this.getTv_comicsdetailbottom_favorite().isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$4$4.2
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
        C2354n.m2374A(getLl_comicsdetailbottom_startview(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailActivity$bindEvent$4$5
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
                Intrinsics.checkNotNullParameter(it, "it");
                ComicsDetailInfoBean value = ComicsViewModel.this.getComicsDetailInfo().getValue();
                if (value == null) {
                    return;
                }
                ComicsChapterViewActivity.INSTANCE.start(this, value);
            }
        }, 1);
    }

    @NotNull
    public final RelativeLayout getBtn_titleBack() {
        return (RelativeLayout) this.btn_titleBack.getValue();
    }

    @NotNull
    public final AppCompatEditText getEd_input_comment_comics() {
        return (AppCompatEditText) this.ed_input_comment_comics.getValue();
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
    public final ShapeableImageView getIv_comicsdetail_img() {
        return (ShapeableImageView) this.iv_comicsdetail_img.getValue();
    }

    @NotNull
    public final ImageView getIv_comicsdetail_top() {
        return (ImageView) this.iv_comicsdetail_top.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_detail_comics;
    }

    @NotNull
    public final View getLl_bottom_tool() {
        return (View) this.ll_bottom_tool.getValue();
    }

    @NotNull
    public final LinearLayout getLl_comicsdetail_bottom() {
        return (LinearLayout) this.ll_comicsdetail_bottom.getValue();
    }

    @NotNull
    public final LinearLayout getLl_comicsdetailbottom_comment_input() {
        return (LinearLayout) this.ll_comicsdetailbottom_comment_input.getValue();
    }

    @NotNull
    public final LinearLayout getLl_comicsdetailbottom_favorite() {
        return (LinearLayout) this.ll_comicsdetailbottom_favorite.getValue();
    }

    @NotNull
    public final LinearLayout getLl_comicsdetailbottom_startview() {
        return (LinearLayout) this.ll_comicsdetailbottom_startview.getValue();
    }

    @NotNull
    public final ComicsDetailInfoFragment getMComicsDetailInfoFragment() {
        ComicsDetailInfoFragment comicsDetailInfoFragment = this.mComicsDetailInfoFragment;
        if (comicsDetailInfoFragment != null) {
            return comicsDetailInfoFragment;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mComicsDetailInfoFragment");
        throw null;
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
    public final RecyclerView getRv_tag() {
        return (RecyclerView) this.rv_tag.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTablayout_comicsdetail() {
        return (SlidingTabLayout) this.tablayout_comicsdetail.getValue();
    }

    @NotNull
    public final TextView getTv_click_favorite() {
        return (TextView) this.tv_click_favorite.getValue();
    }

    @NotNull
    public final TextView getTv_comicsdetail_category() {
        return (TextView) this.tv_comicsdetail_category.getValue();
    }

    @NotNull
    public final TextView getTv_comicsdetail_chaptercount() {
        return (TextView) this.tv_comicsdetail_chaptercount.getValue();
    }

    @NotNull
    public final TextView getTv_comicsdetail_description() {
        return (TextView) this.tv_comicsdetail_description.getValue();
    }

    @NotNull
    public final FollowTextView getTv_comicsdetail_favorite() {
        return (FollowTextView) this.tv_comicsdetail_favorite.getValue();
    }

    @NotNull
    public final TextView getTv_comicsdetail_name() {
        return (TextView) this.tv_comicsdetail_name.getValue();
    }

    @NotNull
    public final TextView getTv_comicsdetailbottom_favorite() {
        return (TextView) this.tv_comicsdetailbottom_favorite.getValue();
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
    public final ViewPager getVp_comicsdetail() {
        return (ViewPager) this.vp_comicsdetail.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
    }

    public final void setMComicsDetailInfoFragment(@NotNull ComicsDetailInfoFragment comicsDetailInfoFragment) {
        Intrinsics.checkNotNullParameter(comicsDetailInfoFragment, "<set-?>");
        this.mComicsDetailInfoFragment = comicsDetailInfoFragment;
    }

    public final void setMCommentFragment(@NotNull CommentFragment commentFragment) {
        Intrinsics.checkNotNullParameter(commentFragment, "<set-?>");
        this.mCommentFragment = commentFragment;
    }

    @NotNull
    public final ComicsViewModel viewModelInstance() {
        return getViewModel();
    }
}
