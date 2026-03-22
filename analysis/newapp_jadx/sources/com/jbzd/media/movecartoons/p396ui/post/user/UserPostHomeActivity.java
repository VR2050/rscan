package com.jbzd.media.movecartoons.p396ui.post.user;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.bean.event.EventFollow;
import com.jbzd.media.movecartoons.bean.response.PostHomeBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.index.post.PostHomeBottomFragment;
import com.jbzd.media.movecartoons.p396ui.post.user.UserPostHomeActivity;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0086\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 f2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001fB\u0007¢\u0006\u0004\be\u0010\u0014J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\n\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\f\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\f\u0010\u0007J\u0017\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u000e\u001a\u00020\rH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\rH\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u0019\u0010\u0017\u001a\u00020\u00052\b\u0010\u0016\u001a\u0004\u0018\u00010\u0015H\u0014¢\u0006\u0004\b\u0017\u0010\u0018J\u000f\u0010\u0019\u001a\u00020\u0005H\u0014¢\u0006\u0004\b\u0019\u0010\u0014R\u001d\u0010\u001f\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u001c\u001a\u0004\b\u001d\u0010\u001eR\u001d\u0010$\u001a\u00020 8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u001c\u001a\u0004\b\"\u0010#R\u001f\u0010(\u001a\u0004\u0018\u00010\u00038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u001c\u001a\u0004\b&\u0010'R\u001d\u0010+\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u001c\u001a\u0004\b*\u0010\u001eR-\u00101\u001a\u0012\u0012\u0004\u0012\u00020\u00030,j\b\u0012\u0004\u0012\u00020\u0003`-8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u001c\u001a\u0004\b/\u00100R\u001d\u00106\u001a\u0002028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b3\u0010\u001c\u001a\u0004\b4\u00105R\"\u00107\u001a\u00020\b8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b7\u00108\u001a\u0004\b9\u0010:\"\u0004\b;\u0010\u000bR1\u0010?\u001a\u0016\u0012\u0006\u0012\u0004\u0018\u00010<0,j\n\u0012\u0006\u0012\u0004\u0018\u00010<`-8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b=\u0010\u001c\u001a\u0004\b>\u00100R\u001d\u0010D\u001a\u00020@8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bA\u0010\u001c\u001a\u0004\bB\u0010CR\u001d\u0010G\u001a\u00020@8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u001c\u001a\u0004\bF\u0010CR\u001d\u0010L\u001a\u00020H8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010\u001c\u001a\u0004\bJ\u0010KR\u001d\u0010O\u001a\u00020@8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bM\u0010\u001c\u001a\u0004\bN\u0010CR\u001d\u0010T\u001a\u00020P8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bQ\u0010\u001c\u001a\u0004\bR\u0010SR\u001d\u0010W\u001a\u00020@8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bU\u0010\u001c\u001a\u0004\bV\u0010CR\u001d\u0010Z\u001a\u00020H8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bX\u0010\u001c\u001a\u0004\bY\u0010KR\u001d\u0010_\u001a\u00020[8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\\\u0010\u001c\u001a\u0004\b]\u0010^R\u001d\u0010d\u001a\u00020`8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\ba\u0010\u001c\u001a\u0004\bb\u0010c¨\u0006g"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/user/UserPostHomeActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "userId", "", "follow", "(Ljava/lang/String;)V", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeBean;", "mPostHomeBean", "setPostHomeInfo", "(Lcom/jbzd/media/movecartoons/bean/response/PostHomeBean;)V", "userHome", "", "isFollow", "toggleLove", "(I)V", "getLayoutId", "()I", "bindEvent", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "onDestroy", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "iv_isposter$delegate", "Lkotlin/Lazy;", "getIv_isposter", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "iv_isposter", "Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_userhome$delegate", "getTablayout_userhome", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_userhome", "mUserId$delegate", "getMUserId", "()Ljava/lang/String;", "mUserId", "iv_isposter_vip$delegate", "getIv_isposter_vip", "iv_isposter_vip", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "tabEntities$delegate", "getTabEntities", "()Ljava/util/ArrayList;", "tabEntities", "Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "civ_head_posthome$delegate", "getCiv_head_posthome", "()Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "civ_head_posthome", "postHomeBean", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeBean;", "getPostHomeBean", "()Lcom/jbzd/media/movecartoons/bean/response/PostHomeBean;", "setPostHomeBean", "Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment;", "fragments$delegate", "getFragments", "fragments", "Landroid/widget/TextView;", "tv_comicsdetail_name$delegate", "getTv_comicsdetail_name", "()Landroid/widget/TextView;", "tv_comicsdetail_name", "fans_posthome$delegate", "getFans_posthome", "fans_posthome", "Landroid/widget/ImageView;", "iv_sex_posthome$delegate", "getIv_sex_posthome", "()Landroid/widget/ImageView;", "iv_sex_posthome", "follows_posthome$delegate", "getFollows_posthome", "follows_posthome", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "tabAdapter$delegate", "getTabAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "tabAdapter", "acc_id_posthome$delegate", "getAcc_id_posthome", "acc_id_posthome", "src_sex_leftline$delegate", "getSrc_sex_leftline", "src_sex_leftline", "Landroidx/viewpager/widget/ViewPager;", "vp_content_userhome$delegate", "getVp_content_userhome", "()Landroidx/viewpager/widget/ViewPager;", "vp_content_userhome", "Lcom/jbzd/media/movecartoons/view/FollowTextView;", "tv_follow_posthome$delegate", "getTv_follow_posthome", "()Lcom/jbzd/media/movecartoons/view/FollowTextView;", "tv_follow_posthome", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class UserPostHomeActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String USERID = "userId";
    public PostHomeBean postHomeBean;

    /* renamed from: mUserId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mUserId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$mUserId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return UserPostHomeActivity.this.getIntent().getStringExtra(UserPostHomeActivity.INSTANCE.getUSERID());
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<PostHomeBottomFragment>>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$fragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<PostHomeBottomFragment> invoke() {
            String mUserId;
            PostHomeBottomFragment[] postHomeBottomFragmentArr = new PostHomeBottomFragment[1];
            mUserId = UserPostHomeActivity.this.getMUserId();
            postHomeBottomFragmentArr[0] = mUserId == null ? null : PostHomeBottomFragment.INSTANCE.newInstance(mUserId);
            return CollectionsKt__CollectionsKt.arrayListOf(postHomeBottomFragmentArr);
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<String>>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$tabEntities$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<String> invoke() {
            return CollectionsKt__CollectionsKt.arrayListOf("帖子");
        }
    });

    /* renamed from: tabAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$tabAdapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList fragments;
            FragmentManager supportFragmentManager = UserPostHomeActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            fragments = UserPostHomeActivity.this.getFragments();
            return new ViewPagerAdapter(supportFragmentManager, fragments, 0, 4, null);
        }
    });

    /* renamed from: civ_head_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy civ_head_posthome = LazyKt__LazyJVMKt.lazy(new Function0<CircleImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$civ_head_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CircleImageView invoke() {
            CircleImageView circleImageView = (CircleImageView) UserPostHomeActivity.this.findViewById(R.id.civ_head_posthome);
            Intrinsics.checkNotNull(circleImageView);
            return circleImageView;
        }
    });

    /* renamed from: tv_follow_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_follow_posthome = LazyKt__LazyJVMKt.lazy(new Function0<FollowTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$tv_follow_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FollowTextView invoke() {
            FollowTextView followTextView = (FollowTextView) UserPostHomeActivity.this.findViewById(R.id.tv_follow_posthome);
            Intrinsics.checkNotNull(followTextView);
            return followTextView;
        }
    });

    /* renamed from: iv_isposter_vip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_isposter_vip = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$iv_isposter_vip$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) UserPostHomeActivity.this.findViewById(R.id.iv_isposter_vip);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: iv_isposter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_isposter = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$iv_isposter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) UserPostHomeActivity.this.findViewById(R.id.iv_isposter);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: iv_sex_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_sex_posthome = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$iv_sex_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) UserPostHomeActivity.this.findViewById(R.id.iv_sex_posthome);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: src_sex_leftline$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy src_sex_leftline = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$src_sex_leftline$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) UserPostHomeActivity.this.findViewById(R.id.src_sex_leftline);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_comicsdetail_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_comicsdetail_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$tv_comicsdetail_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) UserPostHomeActivity.this.findViewById(R.id.tv_comicsdetail_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: acc_id_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy acc_id_posthome = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$acc_id_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) UserPostHomeActivity.this.findViewById(R.id.acc_id_posthome);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: fans_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fans_posthome = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$fans_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) UserPostHomeActivity.this.findViewById(R.id.fans_posthome);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: follows_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy follows_posthome = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$follows_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) UserPostHomeActivity.this.findViewById(R.id.follows_posthome);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: vp_content_userhome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content_userhome = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$vp_content_userhome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) UserPostHomeActivity.this.findViewById(R.id.vp_content_userhome);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tablayout_userhome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tablayout_userhome = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$tablayout_userhome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) UserPostHomeActivity.this.findViewById(R.id.tablayout_userhome);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\t\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000e¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/user/UserPostHomeActivity$Companion;", "", "Landroid/content/Context;", "context", "", "userId", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "USERID", "Ljava/lang/String;", "getUSERID", "()Ljava/lang/String;", "setUSERID", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getUSERID() {
            return UserPostHomeActivity.USERID;
        }

        public final void setUSERID(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            UserPostHomeActivity.USERID = str;
        }

        public final void start(@NotNull Context context, @NotNull String userId) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(userId, "userId");
            Intent intent = new Intent(context, (Class<?>) UserPostHomeActivity.class);
            intent.putExtra(UserPostHomeActivity.INSTANCE.getUSERID(), userId);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void follow(final String userId) {
        C0917a c0917a = C0917a.f372a;
        Class cls = Boolean.TYPE;
        HashMap m595Q = C1499a.m595Q("id", userId);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/doFollow", cls, m595Q, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$follow$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                invoke2(bool);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable Boolean bool) {
                if (bool == null) {
                    return;
                }
                String str = userId;
                UserPostHomeActivity userPostHomeActivity = this;
                boolean booleanValue = bool.booleanValue();
                C4909c.m5569b().m5574g(new EventFollow(str, booleanValue ? "y" : "n"));
                if (booleanValue) {
                    userPostHomeActivity.toggleLove(1);
                } else {
                    userPostHomeActivity.toggleLove(0);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$follow$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<PostHomeBottomFragment> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMUserId() {
        return (String) this.mUserId.getValue();
    }

    private final ViewPagerAdapter getTabAdapter() {
        return (ViewPagerAdapter) this.tabAdapter.getValue();
    }

    private final ArrayList<String> getTabEntities() {
        return (ArrayList) this.tabEntities.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setPostHomeInfo(final PostHomeBean mPostHomeBean) {
        C2354n.m2374A(getTv_follow_posthome(), 0L, new Function1<FollowTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$setPostHomeInfo$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                if (UserPostHomeActivity.this.getPostHomeBean() != null) {
                    if (Intrinsics.areEqual(UserPostHomeActivity.this.getPostHomeBean().is_follow, "y")) {
                        UserPostHomeActivity.this.getPostHomeBean().is_follow = "n";
                        UserPostHomeActivity.this.getTv_follow_posthome().setText("+关注");
                        UserPostHomeActivity.this.getTv_follow_posthome().setTextColor(UserPostHomeActivity.this.getResources().getColor(R.color.black));
                        UserPostHomeActivity.this.getTv_follow_posthome().setSelected(false);
                    } else {
                        UserPostHomeActivity.this.getPostHomeBean().is_follow = "y";
                        UserPostHomeActivity.this.getTv_follow_posthome().setText("已关注");
                        UserPostHomeActivity.this.getTv_follow_posthome().setTextColor(UserPostHomeActivity.this.getResources().getColor(R.color.black40));
                        UserPostHomeActivity.this.getTv_follow_posthome().setSelected(true);
                    }
                }
                UserPostHomeActivity userPostHomeActivity = UserPostHomeActivity.this;
                String str = mPostHomeBean.user_id;
                Intrinsics.checkNotNullExpressionValue(str, "mPostHomeBean.user_id");
                userPostHomeActivity.follow(str);
            }
        }, 1);
        setPostHomeBean(mPostHomeBean);
        C2354n.m2467d2(this).m3298p(mPostHomeBean.img).m3292f0().m757R(getCiv_head_posthome());
        getIv_isposter_vip().setVisibility(Intrinsics.areEqual(mPostHomeBean.is_vip, "y") ? 0 : 8);
        getIv_isposter().setVisibility(Intrinsics.areEqual(mPostHomeBean.is_up, "y") ? 0 : 8);
        if (Intrinsics.areEqual(mPostHomeBean.sex, "0")) {
            getIv_sex_posthome().setVisibility(8);
            getSrc_sex_leftline().setVisibility(8);
        } else {
            getIv_sex_posthome().setVisibility(0);
            getSrc_sex_leftline().setVisibility(0);
            if (Intrinsics.areEqual(mPostHomeBean.sex, "1")) {
                C2354n.m2467d2(this).m3297o(Integer.valueOf(R.drawable.icon_sexfemale)).m757R(getIv_sex_posthome());
            } else {
                C2354n.m2467d2(this).m3297o(Integer.valueOf(R.drawable.icon_sexmale)).m757R(getIv_sex_posthome());
            }
        }
        getIv_isposter().setVisibility(Intrinsics.areEqual(mPostHomeBean.is_up, "y") ? 0 : 8);
        getTv_comicsdetail_name().setText(mPostHomeBean.nickname);
        getAcc_id_posthome().setText(Intrinsics.stringPlus("暗网ID：", mPostHomeBean.user_id));
        getFans_posthome().setText(Intrinsics.stringPlus("粉丝 ", mPostHomeBean.fans));
        getFollows_posthome().setText(Intrinsics.stringPlus("关注 ", mPostHomeBean.follow));
        getTv_follow_posthome().setText(Intrinsics.areEqual(mPostHomeBean.is_follow, "y") ? "已关注" : "+关注");
        getTv_follow_posthome().setSelected(Intrinsics.areEqual(mPostHomeBean.is_follow, "y"));
        getTabEntities().clear();
        getFragments().clear();
        ArrayList<String> tabEntities = getTabEntities();
        StringBuilder m586H = C1499a.m586H("帖子(");
        m586H.append((Object) getPostHomeBean().post_count);
        m586H.append(')');
        tabEntities.add(0, m586H.toString());
        ArrayList<PostHomeBottomFragment> fragments = getFragments();
        PostHomeBottomFragment.Companion companion = PostHomeBottomFragment.INSTANCE;
        String str = getPostHomeBean().user_id;
        Intrinsics.checkNotNullExpressionValue(str, "postHomeBean.user_id");
        fragments.add(companion.newInstance(str));
        ViewPager vp_content_userhome = getVp_content_userhome();
        vp_content_userhome.setOffscreenPageLimit(getTabEntities().size());
        vp_content_userhome.setAdapter(getTabAdapter());
        vp_content_userhome.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$setPostHomeInfo$2$1
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
        SlidingTabLayout tablayout_userhome = getTablayout_userhome();
        ViewPager vp_content_userhome2 = getVp_content_userhome();
        Object[] array = getTabEntities().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tablayout_userhome.m4011e(vp_content_userhome2, (String[]) array);
        if (!getTabEntities().isEmpty()) {
            getVp_content_userhome().setCurrentItem(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void toggleLove(final int isFollow) {
        getTv_follow_posthome().post(new Runnable() { // from class: b.a.a.a.t.k.g.a
            @Override // java.lang.Runnable
            public final void run() {
                UserPostHomeActivity.m5973toggleLove$lambda5(isFollow, this);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: toggleLove$lambda-5, reason: not valid java name */
    public static final void m5973toggleLove$lambda5(int i2, UserPostHomeActivity this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 == 0) {
            this$0.getTv_follow_posthome().setText("+关注");
            this$0.getTv_follow_posthome().setTextColor(this$0.getResources().getColor(R.color.black40));
            this$0.getTv_follow_posthome().setBackground(this$0.getDrawable(R.drawable.state_follow_style));
        } else {
            this$0.getTv_follow_posthome().setText("已关注");
            this$0.getTv_follow_posthome().setTextColor(this$0.getResources().getColor(R.color.black40));
            this$0.getTv_follow_posthome().setBackground(this$0.getDrawable(R.drawable.btn_alertleave_pressed));
            this$0.getTv_follow_posthome().setSelected(i2 == 1);
        }
    }

    private final void userHome(String userId) {
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("id", userId);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/home", PostHomeBean.class, m595Q, new Function1<PostHomeBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$userHome$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PostHomeBean postHomeBean) {
                invoke2(postHomeBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PostHomeBean postHomeBean) {
                if (postHomeBean != null) {
                    UserPostHomeActivity.this.setPostHomeInfo(postHomeBean);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.user.UserPostHomeActivity$userHome$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        String str;
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
            C2354n.m2467d2(this).m3297o(Integer.valueOf(R.mipmap.ic_launcher_51)).m3290d0().m757R(getCiv_head_posthome());
        } else {
            C2354n.m2467d2(this).m3297o(Integer.valueOf(R.mipmap.ic_launcher)).m3290d0().m757R(getCiv_head_posthome());
        }
        String mUserId = getMUserId();
        if (mUserId == null) {
            return;
        }
        userHome(mUserId);
    }

    @NotNull
    public final TextView getAcc_id_posthome() {
        return (TextView) this.acc_id_posthome.getValue();
    }

    @NotNull
    public final CircleImageView getCiv_head_posthome() {
        return (CircleImageView) this.civ_head_posthome.getValue();
    }

    @NotNull
    public final TextView getFans_posthome() {
        return (TextView) this.fans_posthome.getValue();
    }

    @NotNull
    public final TextView getFollows_posthome() {
        return (TextView) this.follows_posthome.getValue();
    }

    @NotNull
    public final ImageTextView getIv_isposter() {
        return (ImageTextView) this.iv_isposter.getValue();
    }

    @NotNull
    public final ImageTextView getIv_isposter_vip() {
        return (ImageTextView) this.iv_isposter_vip.getValue();
    }

    @NotNull
    public final ImageView getIv_sex_posthome() {
        return (ImageView) this.iv_sex_posthome.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_userpost_home;
    }

    @NotNull
    public final PostHomeBean getPostHomeBean() {
        PostHomeBean postHomeBean = this.postHomeBean;
        if (postHomeBean != null) {
            return postHomeBean;
        }
        Intrinsics.throwUninitializedPropertyAccessException("postHomeBean");
        throw null;
    }

    @NotNull
    public final ImageView getSrc_sex_leftline() {
        return (ImageView) this.src_sex_leftline.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTablayout_userhome() {
        return (SlidingTabLayout) this.tablayout_userhome.getValue();
    }

    @NotNull
    public final TextView getTv_comicsdetail_name() {
        return (TextView) this.tv_comicsdetail_name.getValue();
    }

    @NotNull
    public final FollowTextView getTv_follow_posthome() {
        return (FollowTextView) this.tv_follow_posthome.getValue();
    }

    @NotNull
    public final ViewPager getVp_content_userhome() {
        return (ViewPager) this.vp_content_userhome.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
    }

    public final void setPostHomeBean(@NotNull PostHomeBean postHomeBean) {
        Intrinsics.checkNotNullParameter(postHomeBean, "<set-?>");
        this.postHomeBean = postHomeBean;
    }
}
