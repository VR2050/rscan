package com.jbzd.media.movecartoons.p396ui.index.post.block;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.PostBlockListBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u0000 \u00172\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001\u0017B\u0007¢\u0006\u0004\b\u0016\u0010\tJ\u0019\u0010\u0006\u001a\u00020\u00052\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003H\u0014¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fR\u001d\u0010\u0015\u001a\u00020\u00108B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/block/ModulePostBlockActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "Landroid/os/Bundle;", "savedInstanceState", "", "onCreate", "(Landroid/os/Bundle;)V", "bindEvent", "()V", "", "getLayoutId", "()I", "", "getTopBarTitle", "()Ljava/lang/String;", "Lcom/jbzd/media/movecartoons/ui/index/post/block/PostBlockListFragment;", "fragment$delegate", "Lkotlin/Lazy;", "getFragment", "()Lcom/jbzd/media/movecartoons/ui/index/post/block/PostBlockListFragment;", "fragment", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ModulePostBlockActivity extends MyThemeActivity<Object> {

    /* renamed from: fragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragment = LazyKt__LazyJVMKt.lazy(new Function0<PostBlockListFragment>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.ModulePostBlockActivity$fragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final PostBlockListFragment invoke() {
            return PostBlockListFragment.INSTANCE.newInstance(new Function1<List<? extends PostBlockListBean.CategoriesBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.ModulePostBlockActivity$fragment$2.1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(List<? extends PostBlockListBean.CategoriesBean> list) {
                    invoke2(list);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull List<? extends PostBlockListBean.CategoriesBean> it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            });
        }
    });

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String block_name = "";

    @NotNull
    private static String block_id = "";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u000e\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0013\u0010\u0014J%\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u0004¢\u0006\u0004\b\b\u0010\tR\"\u0010\n\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR\"\u0010\u0010\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0010\u0010\u000b\u001a\u0004\b\u0011\u0010\r\"\u0004\b\u0012\u0010\u000f¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/block/ModulePostBlockActivity$Companion;", "", "Landroid/content/Context;", "context", "", "blockName", "blockId", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V", BaseCommonPostListFragment.KEY_BLOCK_ID, "Ljava/lang/String;", "getBlock_id", "()Ljava/lang/String;", "setBlock_id", "(Ljava/lang/String;)V", "block_name", "getBlock_name", "setBlock_name", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getBlock_id() {
            return ModulePostBlockActivity.block_id;
        }

        @NotNull
        public final String getBlock_name() {
            return ModulePostBlockActivity.block_name;
        }

        public final void setBlock_id(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            ModulePostBlockActivity.block_id = str;
        }

        public final void setBlock_name(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            ModulePostBlockActivity.block_name = str;
        }

        public final void start(@NotNull Context context, @NotNull String blockName, @NotNull String blockId) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(blockName, "blockName");
            Intrinsics.checkNotNullParameter(blockId, "blockId");
            setBlock_name(blockName);
            setBlock_id(blockId);
            context.startActivity(new Intent(context, (Class<?>) ModulePostBlockActivity.class));
        }
    }

    private final PostBlockListFragment getFragment() {
        return (PostBlockListFragment) this.fragment.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_postblock_module;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "推荐圈子";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        getSupportFragmentManager().beginTransaction().replace(R.id.frag_content, getFragment()).commit();
    }
}
