package com.jbzd.media.movecartoons.p396ui.index.selected.child;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.HomeVideoGroupBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.search.ModuleDetailActivity;
import com.jbzd.media.movecartoons.view.video.ListPlayerView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 F2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001FB\u0007¢\u0006\u0004\bE\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0019\u0010\b\u001a\u00020\u00032\b\u0010\u0007\u001a\u0004\u0018\u00010\u0006H\u0014¢\u0006\u0004\b\b\u0010\tJG\u0010\u0010\u001a\u00020\u00032\b\u0010\u000b\u001a\u0004\u0018\u00010\n2\"\u0010\u000e\u001a\u001e\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n0\fj\u000e\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n`\r2\n\b\u0002\u0010\u000f\u001a\u0004\u0018\u00010\n¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0012\u0010\u0005J\r\u0010\u0014\u001a\u00020\u0013¢\u0006\u0004\b\u0014\u0010\u0015J\r\u0010\u0016\u001a\u00020\u0013¢\u0006\u0004\b\u0016\u0010\u0015J!\u0010\u001a\u001a\u00020\u00032\b\u0010\u0018\u001a\u0004\u0018\u00010\u00172\b\u0010\u0019\u001a\u0004\u0018\u00010\n¢\u0006\u0004\b\u001a\u0010\u001bJ!\u0010\u001e\u001a\u00020\u00032\b\u0010\u001d\u001a\u0004\u0018\u00010\u001c2\b\u0010\u0019\u001a\u0004\u0018\u00010\n¢\u0006\u0004\b\u001e\u0010\u001fJ\r\u0010 \u001a\u00020\u0003¢\u0006\u0004\b \u0010\u0005J\r\u0010!\u001a\u00020\u0003¢\u0006\u0004\b!\u0010\u0005J\u000f\u0010\"\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\"\u0010\u0005J\u000f\u0010$\u001a\u00020#H\u0016¢\u0006\u0004\b$\u0010%J\u000f\u0010&\u001a\u00020\u0003H\u0016¢\u0006\u0004\b&\u0010\u0005R\u001d\u0010*\u001a\u00020\u00138B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b'\u0010(\u001a\u0004\b)\u0010\u0015R\u0018\u0010,\u001a\u0004\u0018\u00010+8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b,\u0010-R\u001d\u00102\u001a\u00020.8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b/\u0010(\u001a\u0004\b0\u00101R\u001f\u00106\u001a\u0004\u0018\u00010\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b3\u0010(\u001a\u0004\b4\u00105R=\u0010:\u001a\"\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n\u0018\u00010\fj\u0010\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\n\u0018\u0001`\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b7\u0010(\u001a\u0004\b8\u00109R\u0018\u0010;\u001a\u0004\u0018\u00010#8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b;\u0010<R\u001d\u0010A\u001a\u00020=8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b>\u0010(\u001a\u0004\b?\u0010@R\u001f\u0010D\u001a\u0004\u0018\u00010\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bB\u0010(\u001a\u0004\bC\u00105¨\u0006G"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "initView", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "", "videoId", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", VideoListActivity.KEY_PARAMS, "api", "refreshPlayList", "(Ljava/lang/String;Ljava/util/HashMap;Ljava/lang/String;)V", "bindEvent", "", "isFlavorShowing", "()Z", "isGroupShowing", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "tag", "canvas", "showFlavor", "(Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;Ljava/lang/String;)V", "Lcom/jbzd/media/movecartoons/bean/response/HomeVideoGroupBean;", "group", "showGroup", "(Lcom/jbzd/media/movecartoons/bean/response/HomeVideoGroupBean;Ljava/lang/String;)V", "hideFlavor", "hideGroup", "initStatusBar", "", "getLayoutId", "()I", "onBackPressed", "mIsShowOnlyOne$delegate", "Lkotlin/Lazy;", "getMIsShowOnlyOne", "mIsShowOnlyOne", "Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment;", "mFragment", "Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment;", "Lcom/jbzd/media/movecartoons/ui/index/selected/child/GroupFragment;", "mGroupFragment$delegate", "getMGroupFragment", "()Lcom/jbzd/media/movecartoons/ui/index/selected/child/GroupFragment;", "mGroupFragment", "mApi$delegate", "getMApi", "()Ljava/lang/String;", "mApi", "mRequestParams$delegate", "getMRequestParams", "()Ljava/util/HashMap;", "mRequestParams", "mExpandHeight", "Ljava/lang/Integer;", "Lcom/jbzd/media/movecartoons/ui/index/selected/child/FlavorFragment;", "mFlavorFragment$delegate", "getMFlavorFragment", "()Lcom/jbzd/media/movecartoons/ui/index/selected/child/FlavorFragment;", "mFlavorFragment", "mInitId$delegate", "getMInitId", "mInitId", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PlayListActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private Integer mExpandHeight;

    @Nullable
    private PlayListFragment mFragment;

    /* renamed from: mInitId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mInitId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$mInitId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            PlayListActivity.this.getIntent().getStringExtra(PlayListFragment.KEY_INIT_ID);
            return PlayListActivity.this.getIntent().getStringExtra(PlayListFragment.KEY_INIT_ID);
        }
    });

    /* renamed from: mRequestParams$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mRequestParams = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$mRequestParams$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final HashMap<String, String> invoke() {
            return (HashMap) PlayListActivity.this.getIntent().getSerializableExtra(PlayListFragment.KEY_REQUEST_PARAMS);
        }
    });

    /* renamed from: mApi$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mApi = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$mApi$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return PlayListActivity.this.getIntent().getStringExtra(PlayListFragment.KEY_API);
        }
    });

    /* renamed from: mIsShowOnlyOne$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mIsShowOnlyOne = LazyKt__LazyJVMKt.lazy(new Function0<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$mIsShowOnlyOne$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Boolean invoke() {
            return Boolean.valueOf(invoke2());
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final boolean invoke2() {
            return PlayListActivity.this.getIntent().getBooleanExtra(PlayListFragment.KEY_SHOW_ONLY_ONE, false);
        }
    });

    /* renamed from: mFlavorFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFlavorFragment = LazyKt__LazyJVMKt.lazy(new Function0<FlavorFragment>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$mFlavorFragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FlavorFragment invoke() {
            return FlavorFragment.INSTANCE.newInstance();
        }
    });

    /* renamed from: mGroupFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mGroupFragment = LazyKt__LazyJVMKt.lazy(new Function0<GroupFragment>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$mGroupFragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final GroupFragment invoke() {
            return GroupFragment.INSTANCE.newInstance();
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010Ja\u0010\r\u001a\u00020\f2\u0006\u0010\u0003\u001a\u00020\u00022\n\b\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u00042(\b\u0002\u0010\b\u001a\"\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0006j\u0010\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0004\u0018\u0001`\u00072\n\b\u0002\u0010\t\u001a\u0004\u0018\u00010\u00042\b\b\u0002\u0010\u000b\u001a\u00020\n¢\u0006\u0004\b\r\u0010\u000e¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListActivity$Companion;", "", "Landroid/content/Context;", "context", "", "videoId", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", VideoListActivity.KEY_PARAMS, "api", "", "isShowOnlyOne", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/util/HashMap;Ljava/lang/String;Z)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @Nullable String videoId, @Nullable HashMap<String, String> params, @Nullable String api, boolean isShowOnlyOne) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) PlayListActivity.class);
            intent.putExtra(PlayListFragment.KEY_INIT_ID, videoId);
            intent.putExtra(PlayListFragment.KEY_REQUEST_PARAMS, params);
            intent.putExtra(PlayListFragment.KEY_API, api);
            intent.putExtra(PlayListFragment.KEY_SHOW_ONLY_ONE, isShowOnlyOne);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    private final String getMApi() {
        return (String) this.mApi.getValue();
    }

    private final FlavorFragment getMFlavorFragment() {
        return (FlavorFragment) this.mFlavorFragment.getValue();
    }

    private final GroupFragment getMGroupFragment() {
        return (GroupFragment) this.mGroupFragment.getValue();
    }

    private final String getMInitId() {
        return (String) this.mInitId.getValue();
    }

    private final boolean getMIsShowOnlyOne() {
        return ((Boolean) this.mIsShowOnlyOne.getValue()).booleanValue();
    }

    private final HashMap<String, String> getMRequestParams() {
        return (HashMap) this.mRequestParams.getValue();
    }

    @SuppressLint({"SetTextI18n"})
    private final void initView() {
        this.mExpandHeight = Integer.valueOf(C2354n.m2513s0(this));
        C2354n.m2374A((ImageView) findViewById(R$id.iv_back), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView) {
                PlayListActivity.this.onBackPressed();
            }
        }, 1);
        PlayListFragment newInstance = PlayListFragment.INSTANCE.newInstance(getMInitId(), getMRequestParams(), getMApi(), getMIsShowOnlyOne());
        this.mFragment = newInstance;
        getSupportFragmentManager().beginTransaction().replace(R.id.frag_content, newInstance).commit();
    }

    public static /* synthetic */ void refreshPlayList$default(PlayListActivity playListActivity, String str, HashMap hashMap, String str2, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            str2 = null;
        }
        playListActivity.refreshPlayList(str, hashMap, str2);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getSupportFragmentManager().beginTransaction().replace(R.id.frag_flavor, getMFlavorFragment()).commit();
        getSupportFragmentManager().beginTransaction().replace(R.id.frag_group, getMGroupFragment()).commit();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_play_list;
    }

    public final void hideFlavor() {
        LinearLayout linearLayout = (LinearLayout) findViewById(R$id.ll_flavorLayout);
        Integer num = this.mExpandHeight;
        C2354n.m2382C1(false, linearLayout, num == null ? 0 : num.intValue(), 100L);
    }

    public final void hideGroup() {
        LinearLayout linearLayout = (LinearLayout) findViewById(R$id.ll_groupLayout);
        Integer num = this.mExpandHeight;
        C2354n.m2382C1(false, linearLayout, num == null ? 0 : num.intValue(), 100L);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void initStatusBar() {
        ImmersionBar.with(this).fitsSystemWindows(false).navigationBarColor("#000000").statusBarDarkFont(true).init();
    }

    public final boolean isFlavorShowing() {
        return ((LinearLayout) findViewById(R$id.ll_flavorLayout)).getLayoutParams().height != 0;
    }

    public final boolean isGroupShowing() {
        return ((LinearLayout) findViewById(R$id.ll_groupLayout)).getLayoutParams().height != 0;
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        ListPlayerView currentPlayer;
        ListPlayerView currentPlayer2;
        PlayListFragment playListFragment = this.mFragment;
        Boolean bool = null;
        if (playListFragment != null && (currentPlayer2 = playListFragment.getCurrentPlayer()) != null) {
            bool = Boolean.valueOf(currentPlayer2.isIfCurrentIsFullscreen());
        }
        if (!Intrinsics.areEqual(bool, Boolean.TRUE)) {
            super.onBackPressed();
            return;
        }
        PlayListFragment playListFragment2 = this.mFragment;
        if (playListFragment2 == null || (currentPlayer = playListFragment2.getCurrentPlayer()) == null) {
            return;
        }
        currentPlayer.clearFullscreenLayout();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        initView();
    }

    public final void refreshPlayList(@Nullable String videoId, @NotNull HashMap<String, String> params, @Nullable String api) {
        Intrinsics.checkNotNullParameter(params, "params");
        if (isFlavorShowing()) {
            hideFlavor();
        }
        if (isGroupShowing()) {
            hideGroup();
        }
        PlayListFragment playListFragment = this.mFragment;
        if (playListFragment == null) {
            return;
        }
        playListFragment.refreshList(videoId, params, api);
    }

    public final void showFlavor(@Nullable final TagBean tag, @Nullable String canvas) {
        String str;
        String str2;
        C2354n.m2374A((ImageView) findViewById(R$id.iv_close), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showFlavor$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView) {
                PlayListActivity.this.hideFlavor();
            }
        }, 1);
        C2354n.m2374A(findViewById(R$id.v_flavorEmpty), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showFlavor$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(View view) {
                PlayListActivity.this.hideFlavor();
            }
        }, 1);
        TextView textView = (TextView) findViewById(R$id.tv_flavorName);
        String str3 = "";
        if (tag == null || (str = tag.name) == null) {
            str = "";
        }
        textView.setText(Intrinsics.stringPlus("#", str));
        LinearLayout linearLayout = (LinearLayout) findViewById(R$id.ll_flavorLayout);
        Integer num = this.mExpandHeight;
        C2354n.m2382C1(true, linearLayout, num == null ? 0 : num.intValue(), 200L);
        C2354n.m2374A((TextView) findViewById(R$id.tv_lookMore), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showFlavor$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView2) {
                PlayListActivity.this.hideFlavor();
            }
        }, 1);
        int i2 = R$id.tv_doCollect;
        ((TextView) findViewById(i2)).setSelected(tag != null ? tag.getHasFollow() : false);
        ((TextView) findViewById(i2)).setText(((TextView) findViewById(i2)).isSelected() ? "已收藏" : "收藏口味");
        C2354n.m2374A((TextView) findViewById(i2), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showFlavor$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView2) {
                String str4;
                PlayListActivity playListActivity = PlayListActivity.this;
                int i3 = R$id.tv_doCollect;
                ((TextView) playListActivity.findViewById(i3)).setSelected(!((TextView) PlayListActivity.this.findViewById(i3)).isSelected());
                TagBean tagBean = tag;
                if (tagBean != null) {
                    tagBean.is_love = ((TextView) PlayListActivity.this.findViewById(i3)).isSelected() ? "y" : "n";
                }
                ((TextView) PlayListActivity.this.findViewById(i3)).setText(((TextView) PlayListActivity.this.findViewById(i3)).isSelected() ? "已收藏" : "收藏口味");
                HomeDataHelper homeDataHelper = HomeDataHelper.INSTANCE;
                final TagBean tagBean2 = tag;
                if (tagBean2 == null || (str4 = tagBean2.f10032id) == null) {
                    str4 = "";
                }
                final PlayListActivity playListActivity2 = PlayListActivity.this;
                HomeDataHelper.doLove$default(homeDataHelper, str4, HomeDataHelper.type_tag, null, null, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showFlavor$4.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        PlayListActivity playListActivity3 = PlayListActivity.this;
                        int i4 = R$id.tv_doCollect;
                        ((TextView) playListActivity3.findViewById(i4)).setSelected(!((TextView) PlayListActivity.this.findViewById(i4)).isSelected());
                        TagBean tagBean3 = tagBean2;
                        if (tagBean3 != null) {
                            tagBean3.is_love = ((TextView) PlayListActivity.this.findViewById(i4)).isSelected() ? "y" : "n";
                        }
                        ((TextView) PlayListActivity.this.findViewById(i4)).setText(((TextView) PlayListActivity.this.findViewById(i4)).isSelected() ? "已收藏" : "收藏口味");
                    }
                }, 12, null);
            }
        }, 1);
        FlavorFragment mFlavorFragment = getMFlavorFragment();
        if (tag != null && (str2 = tag.f10032id) != null) {
            str3 = str2;
        }
        mFlavorFragment.updateTagsAndCanvas(str3, canvas);
    }

    public final void showGroup(@Nullable final HomeVideoGroupBean group, @Nullable String canvas) {
        String str;
        String str2;
        C2354n.m2374A((ImageView) findViewById(R$id.iv_closeGroup), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showGroup$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView) {
                PlayListActivity.this.hideGroup();
            }
        }, 1);
        C2354n.m2374A(findViewById(R$id.v_groupEmpty), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showGroup$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(View view) {
                PlayListActivity.this.hideGroup();
            }
        }, 1);
        TextView textView = (TextView) findViewById(R$id.tv_groupName);
        String str3 = "";
        if (group == null || (str = group.name) == null) {
            str = "";
        }
        textView.setText(str);
        LinearLayout linearLayout = (LinearLayout) findViewById(R$id.ll_groupLayout);
        Integer num = this.mExpandHeight;
        C2354n.m2382C1(true, linearLayout, num == null ? 0 : num.intValue(), 200L);
        C2354n.m2374A((TextView) findViewById(R$id.tv_lookMore), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showGroup$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView2) {
                String str4;
                PlayListActivity.this.hideGroup();
                ModuleDetailActivity.Companion companion = ModuleDetailActivity.INSTANCE;
                PlayListActivity playListActivity = PlayListActivity.this;
                HomeVideoGroupBean homeVideoGroupBean = group;
                String str5 = "";
                if (homeVideoGroupBean != null && (str4 = homeVideoGroupBean.f9960id) != null) {
                    str5 = str4;
                }
                companion.start(playListActivity, str5, homeVideoGroupBean == null ? null : homeVideoGroupBean.name);
            }
        }, 1);
        C2354n.m2374A((TextView) findViewById(R$id.tv_lookGroupMore), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showGroup$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView2) {
                String str4;
                PlayListActivity.this.hideGroup();
                ModuleDetailActivity.Companion companion = ModuleDetailActivity.INSTANCE;
                PlayListActivity playListActivity = PlayListActivity.this;
                HomeVideoGroupBean homeVideoGroupBean = group;
                String str5 = "";
                if (homeVideoGroupBean != null && (str4 = homeVideoGroupBean.f9960id) != null) {
                    str5 = str4;
                }
                companion.start(playListActivity, str5, homeVideoGroupBean == null ? null : homeVideoGroupBean.name);
            }
        }, 1);
        int i2 = R$id.tv_doGroupCollect;
        ((TextView) findViewById(i2)).setSelected(group != null ? group.getHasFollow() : false);
        ((TextView) findViewById(i2)).setText(((TextView) findViewById(i2)).isSelected() ? "已收藏" : "收藏合集");
        C2354n.m2374A((TextView) findViewById(i2), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showGroup$5
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView2) {
                String str4;
                PlayListActivity playListActivity = PlayListActivity.this;
                int i3 = R$id.tv_doGroupCollect;
                ((TextView) playListActivity.findViewById(i3)).setSelected(!((TextView) PlayListActivity.this.findViewById(i3)).isSelected());
                HomeVideoGroupBean homeVideoGroupBean = group;
                if (homeVideoGroupBean != null) {
                    homeVideoGroupBean.is_love = ((TextView) PlayListActivity.this.findViewById(i3)).isSelected() ? "y" : "n";
                }
                ((TextView) PlayListActivity.this.findViewById(i3)).setText(((TextView) PlayListActivity.this.findViewById(i3)).isSelected() ? "已收藏" : "收藏合集");
                HomeDataHelper homeDataHelper = HomeDataHelper.INSTANCE;
                final HomeVideoGroupBean homeVideoGroupBean2 = group;
                if (homeVideoGroupBean2 == null || (str4 = homeVideoGroupBean2.f9960id) == null) {
                    str4 = "";
                }
                final PlayListActivity playListActivity2 = PlayListActivity.this;
                HomeDataHelper.doLove$default(homeDataHelper, str4, "3", null, null, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$showGroup$5.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        PlayListActivity playListActivity3 = PlayListActivity.this;
                        int i4 = R$id.tv_doGroupCollect;
                        ((TextView) playListActivity3.findViewById(i4)).setSelected(!((TextView) PlayListActivity.this.findViewById(i4)).isSelected());
                        HomeVideoGroupBean homeVideoGroupBean3 = homeVideoGroupBean2;
                        if (homeVideoGroupBean3 != null) {
                            homeVideoGroupBean3.is_love = ((TextView) PlayListActivity.this.findViewById(i4)).isSelected() ? "y" : "n";
                        }
                        ((TextView) PlayListActivity.this.findViewById(i4)).setText(((TextView) PlayListActivity.this.findViewById(i4)).isSelected() ? "已收藏" : "收藏合集");
                    }
                }, 12, null);
            }
        }, 1);
        GroupFragment mGroupFragment = getMGroupFragment();
        if (group != null && (str2 = group.f9960id) != null) {
            str3 = str2;
        }
        mGroupFragment.updateGroupIdAndCanvas(str3, canvas);
    }
}
