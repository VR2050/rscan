package com.jbzd.media.movecartoons.p396ui.post;

import android.content.Context;
import android.content.Intent;
import android.widget.TextView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.TagSubBean;
import com.jbzd.media.movecartoons.p396ui.post.PostVideoTagChooseActivity;
import com.jbzd.media.movecartoons.p396ui.post.SelectVideoTagsFragment;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import java.util.ArrayList;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 \u001d2\u00020\u0001:\u0001\u001dB\u0007¢\u0006\u0004\b\u001c\u0010\tJ\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\r\u0010\tJ\u000f\u0010\u000e\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\nH\u0016¢\u0006\u0004\b\u0010\u0010\fR\u001d\u0010\u0016\u001a\u00020\u00118B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015R\u001d\u0010\u001b\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0013\u001a\u0004\b\u0019\u0010\u001a¨\u0006\u001e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/PostVideoTagChooseActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "dpValue", "", "dp2px", "(F)I", "", "bindEvent", "()V", "", "getRightTitle", "()Ljava/lang/String;", "clickRight", "getLayoutId", "()I", "getTopBarTitle", "Lcom/jbzd/media/movecartoons/ui/post/SelectVideoTagsFragment;", "fragment$delegate", "Lkotlin/Lazy;", "getFragment", "()Lcom/jbzd/media/movecartoons/ui/post/SelectVideoTagsFragment;", "fragment", "Landroid/widget/TextView;", "tv_titleRight$delegate", "getTv_titleRight", "()Landroid/widget/TextView;", "tv_titleRight", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostVideoTagChooseActivity extends BaseActivity {

    @Nullable
    private static ArrayList<TagSubBean> allTagss;

    @Nullable
    private static ArrayList<TagSubBean> mSelectedTags;

    /* renamed from: fragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragment = LazyKt__LazyJVMKt.lazy(new Function0<SelectVideoTagsFragment>() { // from class: com.jbzd.media.movecartoons.ui.post.PostVideoTagChooseActivity$fragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SelectVideoTagsFragment invoke() {
            SelectVideoTagsFragment.Companion companion = SelectVideoTagsFragment.INSTANCE;
            PostVideoTagChooseActivity.Companion companion2 = PostVideoTagChooseActivity.INSTANCE;
            return companion.newInstance(companion2.getMSelectedTags(), companion2.getAllTagss());
        }
    });

    /* renamed from: tv_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.PostVideoTagChooseActivity$tv_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostVideoTagChooseActivity.this.findViewById(R.id.tv_titleRight);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static Function1<? super ArrayList<TagSubBean>, Unit> mComplete = new Function1<ArrayList<TagSubBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostVideoTagChooseActivity$Companion$mComplete$1
        @Override // kotlin.jvm.functions.Function1
        public /* bridge */ /* synthetic */ Unit invoke(ArrayList<TagSubBean> arrayList) {
            invoke2(arrayList);
            return Unit.INSTANCE;
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final void invoke2(@NotNull ArrayList<TagSubBean> it) {
            Intrinsics.checkNotNullParameter(it, "it");
        }
    };

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0017\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b \u0010!J\u0082\u0001\u0010\u000f\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u000223\b\u0002\u0010\f\u001a-\u0012#\u0012!\u0012\u0004\u0012\u00020\u00060\u0005j\b\u0012\u0004\u0012\u00020\u0006`\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0004\u0012\u00020\u000b0\u00042\u001a\u0010\r\u001a\u0016\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005j\n\u0012\u0004\u0012\u00020\u0006\u0018\u0001`\u00072\u001a\u0010\u000e\u001a\u0016\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005j\n\u0012\u0004\u0012\u00020\u0006\u0018\u0001`\u0007¢\u0006\u0004\b\u000f\u0010\u0010RM\u0010\u0011\u001a-\u0012#\u0012!\u0012\u0004\u0012\u00020\u00060\u0005j\b\u0012\u0004\u0012\u00020\u0006`\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0004\u0012\u00020\u000b0\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014\"\u0004\b\u0015\u0010\u0016R6\u0010\u0017\u001a\u0016\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005j\n\u0012\u0004\u0012\u00020\u0006\u0018\u0001`\u00078\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0017\u0010\u0018\u001a\u0004\b\u0019\u0010\u001a\"\u0004\b\u001b\u0010\u001cR6\u0010\u001d\u001a\u0016\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005j\n\u0012\u0004\u0012\u00020\u0006\u0018\u0001`\u00078\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001d\u0010\u0018\u001a\u0004\b\u001e\u0010\u001a\"\u0004\b\u001f\u0010\u001c¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/PostVideoTagChooseActivity$Companion;", "", "Landroid/content/Context;", "context", "Lkotlin/Function1;", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/TagSubBean;", "Lkotlin/collections/ArrayList;", "Lkotlin/ParameterName;", "name", "tags", "", "complete", "selectedTags", "allTags", "start", "(Landroid/content/Context;Lkotlin/jvm/functions/Function1;Ljava/util/ArrayList;Ljava/util/ArrayList;)V", "mComplete", "Lkotlin/jvm/functions/Function1;", "getMComplete", "()Lkotlin/jvm/functions/Function1;", "setMComplete", "(Lkotlin/jvm/functions/Function1;)V", "allTagss", "Ljava/util/ArrayList;", "getAllTagss", "()Ljava/util/ArrayList;", "setAllTagss", "(Ljava/util/ArrayList;)V", "mSelectedTags", "getMSelectedTags", "setMSelectedTags", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ void start$default(Companion companion, Context context, Function1 function1, ArrayList arrayList, ArrayList arrayList2, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                function1 = new Function1<ArrayList<TagSubBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostVideoTagChooseActivity$Companion$start$1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(ArrayList<TagSubBean> arrayList3) {
                        invoke2(arrayList3);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull ArrayList<TagSubBean> it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                    }
                };
            }
            companion.start(context, function1, arrayList, arrayList2);
        }

        @Nullable
        public final ArrayList<TagSubBean> getAllTagss() {
            return PostVideoTagChooseActivity.allTagss;
        }

        @NotNull
        public final Function1<ArrayList<TagSubBean>, Unit> getMComplete() {
            return PostVideoTagChooseActivity.mComplete;
        }

        @Nullable
        public final ArrayList<TagSubBean> getMSelectedTags() {
            return PostVideoTagChooseActivity.mSelectedTags;
        }

        public final void setAllTagss(@Nullable ArrayList<TagSubBean> arrayList) {
            PostVideoTagChooseActivity.allTagss = arrayList;
        }

        public final void setMComplete(@NotNull Function1<? super ArrayList<TagSubBean>, Unit> function1) {
            Intrinsics.checkNotNullParameter(function1, "<set-?>");
            PostVideoTagChooseActivity.mComplete = function1;
        }

        public final void setMSelectedTags(@Nullable ArrayList<TagSubBean> arrayList) {
            PostVideoTagChooseActivity.mSelectedTags = arrayList;
        }

        public final void start(@NotNull Context context, @NotNull Function1<? super ArrayList<TagSubBean>, Unit> complete, @Nullable ArrayList<TagSubBean> selectedTags, @Nullable ArrayList<TagSubBean> allTags) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(complete, "complete");
            context.startActivity(new Intent(context, (Class<?>) PostVideoTagChooseActivity.class));
            setMComplete(complete);
            setMSelectedTags(selectedTags);
            setAllTagss(allTags);
        }
    }

    private final int dp2px(float dpValue) {
        return C2354n.m2425R(this, dpValue);
    }

    private final SelectVideoTagsFragment getFragment() {
        return (SelectVideoTagsFragment) this.fragment.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        ImmersionBar.with(this).fitsSystemWindows(false).navigationBarColor("#000000").statusBarDarkFont(true).init();
        getTv_titleRight().setBackground(getResources().getDrawable(R.drawable.btn_orange_style));
        getSupportFragmentManager().beginTransaction().replace(R.id.frag_content, getFragment()).commit();
        ArrayList<TagSubBean> arrayList = mSelectedTags;
        int size = arrayList != null ? arrayList.size() : 0;
        if (size > 0) {
            setRightTitle(size + "/3");
            return;
        }
        setRightTitle(size + "/3");
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void clickRight() {
        super.clickRight();
        ArrayList<TagSubBean> selects = getFragment().getSelects();
        if (selects.size() <= 0) {
            C2354n.m2449Z("至少选择一个板块");
        } else {
            mComplete.invoke(selects);
            onBackPressed();
        }
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_select_tags;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getRightTitle() {
        return "确定";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "选择视频标签";
    }

    @NotNull
    public final TextView getTv_titleRight() {
        return (TextView) this.tv_titleRight.getValue();
    }
}
