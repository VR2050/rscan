package com.jbzd.media.movecartoons.p396ui.dialog;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.p396ui.dialog.ShareBottomDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.ShareBottomDialog$linkAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/dialog/ShareBottomDialog$linkAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomDialog$linkAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShareBottomDialog$linkAdapter$2 extends Lambda implements Function0<C37331> {
    public final /* synthetic */ ShareBottomDialog this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ShareBottomDialog$linkAdapter$2(ShareBottomDialog shareBottomDialog) {
        super(0);
        this.this$0 = shareBottomDialog;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5788invoke$lambda2$lambda1(ShareBottomDialog this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type kotlin.String");
        String str = (String) obj;
        Object systemService = this$0.requireContext().getApplicationContext().getSystemService("clipboard");
        Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.content.ClipboardManager");
        ((ClipboardManager) systemService).setPrimaryClip(ClipData.newPlainText(str, str));
        C2354n.m2409L1("已复制到剪切板");
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$linkAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C37331 invoke() {
        ?? r0 = new BaseQuickAdapter<String, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$linkAdapter$2.1
            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull String item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                helper.m3919i(R.id.tv_name, Intrinsics.stringPlus("下载链接", Integer.valueOf(helper.getLayoutPosition() + 1)));
            }
        };
        final ShareBottomDialog shareBottomDialog = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.x
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                ShareBottomDialog$linkAdapter$2.m5788invoke$lambda2$lambda1(ShareBottomDialog.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
